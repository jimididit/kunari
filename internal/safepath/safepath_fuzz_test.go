package safepath

import "testing"

func FuzzClean(f *testing.F) {
	f.Add("/tmp/ok")
	f.Add("../etc/passwd")
	f.Add("")
	f.Add("C:\\Windows\\System32\\a.env")
	f.Add("a\x00b")
	f.Fuzz(func(t *testing.T, p string) {
		_, _ = Clean(p)
	})
}
