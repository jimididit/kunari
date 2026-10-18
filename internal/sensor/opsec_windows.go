//go:build windows

package sensor

// On Windows, Go's permission bits are not a reliable ACL check. Operators should
// restrict NTFS ACLs on sentinel.json, ingest.secret, and data_dir (see SECURITY.md).
func hardenPrivateFile(path string) error { return nil }

func hardenPrivateDir(path string) error { return nil }
