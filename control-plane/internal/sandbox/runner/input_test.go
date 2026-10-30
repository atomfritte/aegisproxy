package runner

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"

	"aegisproxy/control-plane/internal/sandbox"
)

func TestReadInputAndVerify(t *testing.T) {
	artifact := bytes.Repeat([]byte("package-bytes "), 100)
	sum256 := sha256.Sum256(artifact)
	sum512 := sha512.Sum512(artifact)

	job := sandbox.Job{
		ID: "job-1", Ecosystem: "npm", Filename: "demo-1.0.0.tgz",
		SHA256: hex.EncodeToString(sum256[:]),
		SHA512: base64.StdEncoding.EncodeToString(sum512[:]),
		Size:   int64(len(artifact)),
	}
	line, _ := json.Marshal(sandbox.RunnerInput{Job: job, ArtifactSize: int64(len(artifact))})
	stream := append(append(line, '\n'), artifact...)

	dst := filepath.Join(t.TempDir(), "a.bin")
	in, art, err := ReadInput(bytes.NewReader(stream), dst)
	if err != nil {
		t.Fatal(err)
	}
	if in.Job.ID != "job-1" || art.Size != int64(len(artifact)) {
		t.Errorf("input = %+v art = %+v", in, art)
	}
	if err := VerifyDigests(job, art); err != nil {
		t.Errorf("verify should pass: %v", err)
	}

	// Tampered digest fails.
	bad := job
	bad.SHA256 = hex.EncodeToString(make([]byte, 32))
	if err := VerifyDigests(bad, art); err == nil {
		t.Error("verify should fail on sha256 mismatch")
	}
	// Format detection.
	if art.Format != "tgz" {
		t.Errorf("format = %s", art.Format)
	}
}

func TestVerifyB64PaddingTolerant(t *testing.T) {
	art := &sandbox.Artifact{SHA512: base64.StdEncoding.EncodeToString([]byte("0123456789"))}
	job := sandbox.Job{SHA512: base64.RawStdEncoding.EncodeToString([]byte("0123456789"))}
	if err := VerifyDigests(job, art); err != nil {
		t.Errorf("padding-tolerant compare failed: %v", err)
	}
}
