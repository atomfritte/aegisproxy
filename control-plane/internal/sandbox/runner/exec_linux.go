//go:build linux

package runner

import (
	"context"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// unprivUID / unprivGID are the sandbox user the analyzed code runs as. The runner itself starts as root to
// prepare observers and bind privileged ports, then every analyzed process is launched dropped to this uid with
// no supplementary groups and no capabilities.
const (
	unprivUID = 1000
	unprivGID = 1000
)

// stracePrefix is the fixed strace invocation. -f follows forks, -ttt gives epoch timestamps, -T the call
// duration, -yy decodes fds (socket peers, resolved paths) and -s 256 keeps enough of each string.
func stracePrefix(stracePath, traceFile string) []string {
	return []string{stracePath, "-f", "-ttt", "-T", "-yy", "-s", "256", "-o", traceFile, "--"}
}

type traceSpec struct {
	argv       []string
	dir        string
	env        []string
	traceFile  string
	timeout    time.Duration
	stracePath string
}

type traceResult struct {
	exitCode   int
	timedOut   bool
	duration   time.Duration
	stdoutTail string
	stderrTail string
}

// runTraced runs spec.argv under strace as the unprivileged user, in its own process group, with a hard timeout.
// On timeout the whole group is killed. It returns the child's exit information; an error is only returned when
// the child could not be started at all.
func runTraced(spec traceSpec) (traceResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), spec.timeout)
	defer cancel()

	full := append(stracePrefix(spec.stracePath, spec.traceFile), spec.argv...)
	cmd := exec.Command(full[0], full[1:]...)
	cmd.Dir = spec.dir
	cmd.Env = spec.env
	out := &tailBuffer{max: 8 << 10}
	errb := &tailBuffer{max: 8 << 10}
	cmd.Stdout = out
	cmd.Stderr = errb
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: unprivUID, Gid: unprivGID, NoSetGroups: true},
		Setpgid:    true,
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return traceResult{}, err
	}
	pgid := cmd.Process.Pid

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var res traceResult
	select {
	case <-ctx.Done():
		res.timedOut = true
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			<-done
		}
	case <-done:
	}
	res.duration = time.Since(start)
	res.stdoutTail = out.String()
	res.stderrTail = errb.String()
	if res.timedOut {
		res.exitCode = -1
	} else if cmd.ProcessState != nil {
		res.exitCode = cmd.ProcessState.ExitCode()
	}
	// Make sure no stray children survive the phase.
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	return res, nil
}

// tailBuffer keeps the last max bytes written to it (for the 8 KiB stdout/stderr tails).
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return printable(t.buf, t.max)
}
