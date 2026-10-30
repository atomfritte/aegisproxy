package runner

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// DNSServer is the fake resolver. It answers every A query with a unique 127.10.x.y address from the collector
// and every AAAA with ::1, so name resolution always "succeeds" and later connects land on a loopback sink that
// can be mapped back to the queried name. Every query is recorded. All other record types get an empty NOERROR.
type DNSServer struct {
	hub *ColHub
	udp net.PacketConn
	tcp net.Listener
}

// StartDNS starts the resolver on udpAddr (UDP) and tcpAddr (TCP). In the sandbox both are 127.0.0.53:53; tests
// pass ephemeral addresses. Either address may be empty to skip that transport.
func StartDNS(hub *ColHub, udpAddr, tcpAddr string) (*DNSServer, error) {
	s := &DNSServer{hub: hub}
	if udpAddr != "" {
		pc, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			return nil, err
		}
		s.udp = pc
		go s.serveUDP()
	}
	if tcpAddr != "" {
		ln, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			if s.udp != nil {
				s.udp.Close()
			}
			return nil, err
		}
		s.tcp = ln
		go s.serveTCP()
	}
	return s, nil
}

// UDPAddr / TCPAddr return the bound addresses (useful when a test binds :0).
func (s *DNSServer) UDPAddr() string {
	if s.udp != nil {
		return s.udp.LocalAddr().String()
	}
	return ""
}
func (s *DNSServer) TCPAddr() string {
	if s.tcp != nil {
		return s.tcp.Addr().String()
	}
	return ""
}

func (s *DNSServer) Close() {
	if s.udp != nil {
		s.udp.Close()
	}
	if s.tcp != nil {
		s.tcp.Close()
	}
}

func (s *DNSServer) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		resp, ok := s.handle(buf[:n])
		if ok {
			_ = s.udp.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = s.udp.WriteTo(resp, addr)
		}
	}
}

func (s *DNSServer) serveTCP() {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go s.serveTCPConn(conn)
	}
}

func (s *DNSServer) serveTCPConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen == 0 || msgLen > 65535 {
			return
		}
		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		resp, ok := s.handle(msg)
		if !ok {
			return
		}
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
		if _, err := conn.Write(append(out[:], resp...)); err != nil {
			return
		}
	}
}

// handle parses one query, records it and builds the response message.
func (s *DNSServer) handle(msg []byte) ([]byte, bool) {
	q, err := parseQuery(msg)
	if err != nil {
		return nil, false
	}
	s.hub.C().RecordDNS(q.name, dnsTypeName(q.qtype))

	resp := buildHeader(q.id, q.qdcount)
	resp = append(resp, msg[12:q.qEnd]...) // echo the question section verbatim

	var answers int
	switch q.qtype {
	case 1: // A
		ip := s.hub.C().AssignIP(q.name)
		resp = appendARecord(resp, net.ParseIP(ip).To4())
		answers = 1
	case 28: // AAAA
		resp = appendAAAARecord(resp, net.IPv6loopback)
		answers = 1
	}
	binary.BigEndian.PutUint16(resp[6:8], uint16(answers)) // ANCOUNT
	return resp, true
}

type dnsQuery struct {
	id      uint16
	qdcount uint16
	name    string
	qtype   uint16
	qEnd    int // offset just past the question (name+qtype+qclass)
}

func parseQuery(msg []byte) (dnsQuery, error) {
	if len(msg) < 12 {
		return dnsQuery{}, errors.New("short dns message")
	}
	q := dnsQuery{
		id:      binary.BigEndian.Uint16(msg[0:2]),
		qdcount: binary.BigEndian.Uint16(msg[4:6]),
	}
	if q.qdcount == 0 {
		return dnsQuery{}, errors.New("no question")
	}
	name, off, err := readName(msg, 12)
	if err != nil {
		return dnsQuery{}, err
	}
	if off+4 > len(msg) {
		return dnsQuery{}, errors.New("truncated question")
	}
	q.name = name
	q.qtype = binary.BigEndian.Uint16(msg[off : off+2])
	q.qEnd = off + 4
	q.qdcount = 1 // we only ever echo one question
	return q, nil
}

// readName reads a (non-compressed) QNAME starting at off, returning the dotted name and the offset past it.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	for {
		if off >= len(msg) {
			return "", 0, errors.New("name overruns message")
		}
		l := int(msg[off])
		if l == 0 {
			off++
			break
		}
		if l&0xc0 != 0 { // compression pointer: not expected in a question, bail
			return "", 0, errors.New("unexpected compression in question")
		}
		off++
		if off+l > len(msg) || len(labels) > 127 {
			return "", 0, errors.New("bad label")
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
	}
	return strings.Join(labels, "."), off, nil
}

func buildHeader(id, qdcount uint16) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:2], id)
	// QR=1, Opcode=0, AA=1, TC=0, RD=0; RA=0, RCODE=0.
	h[2] = 0x84
	h[3] = 0x00
	binary.BigEndian.PutUint16(h[4:6], qdcount) // QDCOUNT
	// ANCOUNT/NSCOUNT/ARCOUNT left zero (ANCOUNT patched by caller).
	return h
}

func appendARecord(resp []byte, ip4 net.IP) []byte {
	if ip4 == nil {
		ip4 = net.IPv4(127, 0, 0, 1).To4()
	}
	resp = append(resp, 0xc0, 0x0c) // name pointer to the question
	resp = appendU16(resp, 1)       // TYPE A
	resp = appendU16(resp, 1)       // CLASS IN
	resp = appendU32(resp, 1)       // TTL 1s
	resp = appendU16(resp, 4)       // RDLENGTH
	return append(resp, ip4...)
}

func appendAAAARecord(resp []byte, ip6 net.IP) []byte {
	resp = append(resp, 0xc0, 0x0c)
	resp = appendU16(resp, 28) // TYPE AAAA
	resp = appendU16(resp, 1)
	resp = appendU32(resp, 1)
	resp = appendU16(resp, 16)
	return append(resp, ip6.To16()...)
}

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }
func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	}
	return "TYPE" + itoa(int(t))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
