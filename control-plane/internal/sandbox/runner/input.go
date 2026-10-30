package runner

import (
	"bufio"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"aegisproxy/control-plane/internal/sandbox"
)

// ReadInput reads one JSON line (RunnerInput) from r, then streams exactly input.ArtifactSize following bytes
// into a file at dst while computing sha256 and sha512. It returns the input and the resulting Artifact
// descriptor (digests + detected format). It does not verify the digests; call VerifyDigests for that.
func ReadInput(r io.Reader, dst string) (*sandbox.RunnerInput, *sandbox.Artifact, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	line, err := br.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, nil, fmt.Errorf("read input line: %w", err)
	}
	var in sandbox.RunnerInput
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(line))), &in); err != nil {
		return nil, nil, fmt.Errorf("parse RunnerInput: %w", err)
	}
	if in.ArtifactSize < 0 || in.ArtifactSize > (4<<30) {
		return nil, nil, fmt.Errorf("implausible artifact size %d", in.ArtifactSize)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	h256 := sha256.New()
	h512 := sha512.New()
	mw := io.MultiWriter(f, h256, h512)
	headBuf := &headCapture{limit: 8}
	tee := io.TeeReader(io.LimitReader(br, in.ArtifactSize), headBuf)

	n, err := io.Copy(mw, tee)
	if err != nil {
		return nil, nil, fmt.Errorf("read artifact: %w", err)
	}
	if n != in.ArtifactSize {
		return nil, nil, fmt.Errorf("short artifact: got %d of %d bytes", n, in.ArtifactSize)
	}
	art := &sandbox.Artifact{
		Filename: in.Job.Filename,
		Size:     n,
		SHA256:   hex.EncodeToString(h256.Sum(nil)),
		SHA512:   base64.StdEncoding.EncodeToString(h512.Sum(nil)),
		Format:   DetectFormat(in.Job.Filename, headBuf.head),
	}
	return &in, art, nil
}

// VerifyDigests compares the computed digests in art against the expected ones in the job (when present). It
// returns a descriptive error on any mismatch so the caller can emit a report with the error and run nothing.
func VerifyDigests(job sandbox.Job, art *sandbox.Artifact) error {
	var problems []string
	if job.SHA256 != "" && !strings.EqualFold(job.SHA256, art.SHA256) {
		problems = append(problems, fmt.Sprintf("sha256 mismatch: expected %s, got %s", job.SHA256, art.SHA256))
	}
	if job.SHA512 != "" && !equalB64(job.SHA512, art.SHA512) {
		problems = append(problems, fmt.Sprintf("sha512 mismatch: expected %s, got %s", job.SHA512, art.SHA512))
	}
	if job.Size > 0 && job.Size != art.Size {
		problems = append(problems, fmt.Sprintf("size mismatch: expected %d, got %d", job.Size, art.Size))
	}
	if len(problems) > 0 {
		return fmt.Errorf("artifact verification failed: %s", strings.Join(problems, "; "))
	}
	return nil
}

// equalB64 compares two standard-base64 strings by their decoded bytes (tolerant of padding differences).
func equalB64(a, b string) bool {
	da, ea := decodeB64Any(a)
	db, eb := decodeB64Any(b)
	if ea != nil || eb != nil {
		return a == b
	}
	if len(da) != len(db) {
		return false
	}
	var diff byte
	for i := range da {
		diff |= da[i] ^ db[i]
	}
	return diff == 0
}

func decodeB64Any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

// headCapture tees the first few bytes of the artifact so DetectFormat can look at the magic.
type headCapture struct {
	head  []byte
	limit int
}

func (h *headCapture) Write(p []byte) (int, error) {
	if len(h.head) < h.limit {
		need := h.limit - len(h.head)
		if need > len(p) {
			need = len(p)
		}
		h.head = append(h.head, p[:need]...)
	}
	return len(p), nil
}
