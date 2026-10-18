package sensor

import "testing"

func FuzzParseESLoggerLine(f *testing.F) {
	f.Add([]byte(`{"event":{"open":{"file":{"path":"/tmp/x"}}},"process":{"audit_token":{"pid":1},"executable":{"path":"/bin/cat"}}}`))
	f.Add([]byte(`{"event":{"rename":{"source":{"path":"/tmp/a"},"destination":{"new_path":{"dir":{"path":"/tmp"},"filename":"b"}}}}}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{}`))
	targets := []Target{{Path: "/tmp/x"}, {Path: "/tmp/a"}, {Path: "/tmp"}}
	f.Fuzz(func(t *testing.T, line []byte) {
		_, _ = ParseESLoggerLine(line, targets)
	})
}

func FuzzMatchAllowlist(f *testing.F) {
	f.Add(`C:\Windows\System32\SearchIndexer.exe`)
	f.Add(`/usr/bin/updatedb`)
	f.Add(`/tmp/evil`)
	f.Add(``)
	list := DefaultAllowlist()
	f.Fuzz(func(t *testing.T, exe string) {
		_, _ = MatchAllowlist(exe, list)
	})
}
