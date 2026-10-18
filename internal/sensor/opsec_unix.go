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
	if mode&0o077 != 0 {
		// Fail closed rather than Chmod(0700): gosec G302 rejects dir modes, and
		// operators should own the ACL fix (mkdir already uses 0700 for new dirs).
		return fmt.Errorf("%s is group/other-accessible (mode %04o); run: chmod 0700 %s", path, mode, path)
	}
	return nil
}
