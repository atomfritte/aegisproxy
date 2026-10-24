package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Round-2 finding 8: an encryption key read from the data directory is flagged.
func TestEncryptionKeyInDataDir(t *testing.T) {
	data, outside := t.TempDir(), t.TempDir()
	t.Setenv("DATA_DIR", data)
	for _, k := range []string{"AEGIS_ENCRYPTION_KEY", "AEGIS_ENCRYPTION_KEY_FILE", "AEGIS_STORAGE"} {
		t.Setenv(k, "")
	}
	key := strings.Repeat("e", 48) + "\n"
	inside := filepath.Join(data, "secrets", "my.key")
	os.MkdirAll(filepath.Dir(inside), 0o700)
	os.WriteFile(inside, []byte(key), 0o600)
	external := filepath.Join(outside, "enc.key")
	os.WriteFile(external, []byte(key), 0o600)

	for _, tc := range []struct {
		name, env, file string
		want            bool
	}{
		{"generated", "", "", true},
		{"environment", strings.Repeat("v", 48), "", false},
		{"file outside DATA_DIR", "", external, false},
		{"file inside DATA_DIR", "", inside, true},
	} {
		t.Setenv("AEGIS_ENCRYPTION_KEY", tc.env)
		t.Setenv("AEGIS_ENCRYPTION_KEY_FILE", tc.file)
		c, err := Load()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if c.EncryptionKeyInDataDir != tc.want {
			t.Errorf("%s: EncryptionKeyInDataDir = %v, want %v", tc.name, c.EncryptionKeyInDataDir, tc.want)
		}
	}
}
