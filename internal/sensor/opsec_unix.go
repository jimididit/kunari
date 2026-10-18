//go:build unix

package sensor

import (
	"fmt"
	"os"
)

// hardenPrivateFile ensures path is not group/other-accessible (mode 0600).
// Readable sentinel.json or ingest secrets disclose watch lists and hub credentials
// to any local user who can read them.
func hardenPrivateFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("%s: expected a file", path)
	}
	mode := st.Mode().Perm()
	if mode&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("%s is group/other-readable (mode %04o); chmod 0600 failed: %w", path, mode, err)
	}
	return nil
}

func hardenPrivateDir(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s: expected a directory", path)
	}
	mode := st.Mode().Perm()
	if mode&0o077 == 0 {
		return nil
	}
	// Directories need owner+x (0700); gosec G302 is aimed at secret files (0600).
	if err := os.Chmod(path, 0o700); err != nil { // #nosec G302 -- private data dir, not a credential file
		return fmt.Errorf("%s is group/other-accessible (mode %04o); chmod 0700 failed: %w", path, mode, err)
	}
	return nil
}
