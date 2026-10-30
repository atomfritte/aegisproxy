package runner

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// Event is one parsed line of `strace -f -ttt -T -yy` output. Unfinished/resumed pairs are merged into a single
// Event. Signal and exit/kill lines are kept as Events with Signal / Exited set.
type Event struct {
	Epoch      float64  // absolute time from -ttt (seconds); 0 if the line had none
	PID        int      // thread/process id from -f
	Name       string   // syscall name ("" for signal/exit lines)
	Args       string   // raw text between the outermost parentheses
	ArgList    []string // Args split at top-level commas (quotes/brackets respected)
	Ret        string   // return value token (e.g. "0", "3", "-1")
	RetDecoded string   // -yy decoration on the return (e.g. the resolved path of an fd), without the <>
	Errno      string   // e.g. "ECONNREFUSED" when the call failed
	Signal     string   // e.g. "SIGSEGV" for `--- SIG... ---` lines
	Exited     bool     // `+++ exited/killed +++`
	ExitInfo   string   // text of the exit/kill line
}

// ParseStrace parses a full strace output stream into events in file order. It tolerates truncation and
// malformed lines (those are skipped). It never returns an error for bad content, only for a read failure.
func ParseStrace(r io.Reader) ([]Event, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20) // allow very long argument lines
	var events []Event
	// pending unfinished calls keyed by pid: the text before "<unfinished ...>".
	pending := map[int]pendingCall{}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		ev, kind, pc := parseLine(line)
		switch kind {
		case lineUnfinished:
			pending[ev.PID] = pc
		case lineResumed:
			if start, ok := pending[ev.PID]; ok {
				delete(pending, ev.PID)
				merged := start.merge(pc)
				if m, ok := finishMerged(ev.PID, start.epoch, merged); ok {
					events = append(events, m)
				}
			}
		case lineComplete:
			events = append(events, ev)
		case lineSignalExit:
			events = append(events, ev)
		}
		if len(events) > 2_000_000 { // hard safety cap: never grow unbounded on a hostile trace
			break
		}
	}
	return events, sc.Err()
}

type pendingCall struct {
	epoch   float64
	pid     int
	name    string
	argHead string // partial args text before "<unfinished ...>"
}

func (p pendingCall) merge(tail pendingCall) string {
	return p.name + "(" + strings.TrimSpace(p.argHead) + tail.argHead
}

type lineKind int

const (
	lineOther lineKind = iota
	lineComplete
	lineUnfinished
	lineResumed
	lineSignalExit
)

// parseLine classifies and parses a single strace line.
func parseLine(line string) (Event, lineKind, pendingCall) {
	var ev Event
	// Leading PID (from -f). strace right-pads pids; there may be extra spaces.
	line = strings.TrimLeft(line, " ")
	pid, rest, ok := leadingInt(line)
	if ok {
		ev.PID = pid
		line = strings.TrimLeft(rest, " ")
	}
	// Leading timestamp (from -ttt): a float like 1700000000.123456.
	if epoch, rest2, ok := leadingFloat(line); ok {
		ev.Epoch = epoch
		line = strings.TrimLeft(rest2, " ")
	}
	switch {
	case strings.HasPrefix(line, "--- "):
		ev.Signal = firstToken(strings.TrimPrefix(line, "--- "))
		ev.ExitInfo = clampStr(strings.Trim(line, "- "), 200)
		return ev, lineSignalExit, pendingCall{}
	case strings.HasPrefix(line, "+++ "):
		ev.Exited = true
		ev.ExitInfo = clampStr(strings.Trim(line, "+ "), 200)
		return ev, lineSignalExit, pendingCall{}
	case strings.HasPrefix(line, "<... "):
		// Resumed: "<... NAME resumed> <rest of args>) = ret"
		inner := strings.TrimPrefix(line, "<... ")
		name := firstToken(inner)
		if i := strings.Index(inner, "resumed>"); i >= 0 {
			tail := inner[i+len("resumed>"):]
			return ev, lineResumed, pendingCall{pid: ev.PID, name: name, argHead: tail}
		}
		return ev, lineOther, pendingCall{}
	}
	// Normal syscall line: NAME(args...) = ret <dur>, possibly ending in "<unfinished ...>".
	name, argsStart := syscallName(line)
	if name == "" {
		return ev, lineOther, pendingCall{}
	}
	ev.Name = name
	body := line[argsStart:] // starts just after '('
	if strings.HasSuffix(strings.TrimRight(body, " "), "<unfinished ...>") {
		head := strings.TrimSuffix(strings.TrimRight(body, " "), "<unfinished ...>")
		return ev, lineUnfinished, pendingCall{epoch: ev.Epoch, pid: ev.PID, name: name, argHead: head}
	}
	fillCall(&ev, name, body)
	return ev, lineComplete, pendingCall{}
}

// finishMerged turns a merged "name(argsAndRet..." string into a completed Event.
func finishMerged(pid int, epoch float64, merged string) (Event, bool) {
	ev := Event{PID: pid, Epoch: epoch}
	name, argsStart := syscallName(merged)
	if name == "" {
		return ev, false
	}
	ev.Name = name
	fillCall(&ev, name, merged[argsStart:])
	return ev, true
}

// fillCall parses "args...) = ret errno (..) <dur>" (body begins just after the opening paren) into the Event.
func fillCall(ev *Event, name, body string) {
	ev.Name = name
	close := matchParen(body)
	if close < 0 {
		ev.Args = clampStr(body, 4096)
		return
	}
	ev.Args = body[:close]
	ev.ArgList = splitTopLevel(ev.Args)
	ret := strings.TrimSpace(body[close+1:])
	parseRet(ev, ret)
}

// parseRet parses the "= 3<path> ECONNREFUSED (..) <0.1>" tail after the args.
func parseRet(ev *Event, ret string) {
	ret = strings.TrimSpace(ret)
	if !strings.HasPrefix(ret, "=") {
		return
	}
	ret = strings.TrimSpace(ret[1:])
	// Drop the trailing <duration>.
	if i := strings.LastIndex(ret, " <"); i >= 0 && strings.HasSuffix(ret, ">") {
		ret = strings.TrimSpace(ret[:i])
	}
	// Return value token, then optional <decoration>, then optional ERRNO (text).
	val := ret
	if sp := strings.IndexByte(ret, ' '); sp >= 0 {
		val = ret[:sp]
		tail := strings.TrimSpace(ret[sp:])
		// Errno token: an uppercase identifier possibly followed by "(...)".
		if tok := firstToken(tail); isErrno(tok) {
			ev.Errno = tok
		}
	}
	// -yy decoration attached to the value, e.g. 3</resolved/path> or 5<TCP:[...]>.
	if lt := strings.IndexByte(val, '<'); lt >= 0 && strings.HasSuffix(val, ">") {
		ev.RetDecoded = val[lt+1 : len(val)-1]
		val = val[:lt]
	}
	ev.Ret = val
}

// syscallName returns the syscall name and the index just past its opening '(' in s, or "" if the line does not
// look like a syscall.
func syscallName(s string) (string, int) {
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '(' {
			if i == 0 {
				return "", -1
			}
			return s[:i], i + 1
		}
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return "", -1
		}
		i++
	}
	return "", -1
}

// matchParen returns the index of the ')' that closes the argument list that starts at the beginning of s
// (s begins just after the opening paren), honoring quoted strings and nested [] {} ().
func matchParen(s string) int {
	depth := 0
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch c {
			case '\\':
				i++ // skip escaped char
			case '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '(', '[', '{':
			depth++
		case ']', '}':
			if depth > 0 {
				depth--
			}
		case ')':
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

// splitTopLevel splits an argument string at top-level commas, honoring quotes and nesting.
func splitTopLevel(s string) []string {
	var out []string
	depth := 0
	inStr := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch c {
			case '\\':
				i++
			case '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if start <= len(s) {
		if tok := strings.TrimSpace(s[start:]); tok != "" || len(out) > 0 {
			out = append(out, tok)
		}
	}
	return out
}

func leadingInt(s string) (int, string, bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, s, false
	}
	// Must be followed by a space (a bare number isn't a pid otherwise).
	if i >= len(s) || s[i] != ' ' {
		return 0, s, false
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, s, false
	}
	return n, s[i:], true
}

func leadingFloat(s string) (float64, string, bool) {
	i := 0
	dot := false
	for i < len(s) {
		c := s[i]
		if c >= '0' && c <= '9' {
			i++
			continue
		}
		if c == '.' && !dot {
			dot = true
			i++
			continue
		}
		break
	}
	if i == 0 || !dot {
		return 0, s, false
	}
	f, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0, s, false
	}
	return f, s[i:], true
}

func firstToken(s string) string {
	s = strings.TrimLeft(s, " ")
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '{' || c == '(' || c == ',' {
			return s[:i]
		}
	}
	return s
}

func isErrno(tok string) bool {
	if len(tok) < 2 || len(tok) > 24 {
		return false
	}
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return tok[0] >= 'A' && tok[0] <= 'Z'
}
