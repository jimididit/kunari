package sensor

import "testing"

func TestParseESLoggerOpen(t *testing.T) {
	line := []byte(`{
	  "time": "2026-10-17T12:00:00Z",
	  "event_type": 10,
	  "process": {
	    "ppid": 1,
	    "audit_token": {"pid": 4242},
	    "executable": {"path": "/bin/cat"}
	  },
	  "event": {
	    "open": {"file": {"path": "/tmp/kunari-canary.env"}}
	  }
	}`)
	targets := []Target{{Path: "/tmp/kunari-canary.env", TokenID: "t1"}}
	touch, ok := ParseESLoggerLine(line, targets)
	if !ok {
		t.Fatal("expected match")
	}
	if touch.Action != "open" || touch.PID != 4242 || touch.Path != "/tmp/kunari-canary.env" {
		t.Fatalf("unexpected touch: %+v", touch)
	}
}

func TestParseESLoggerWriteUnwatched(t *testing.T) {
	line := []byte(`{"event":{"write":{"target":{"path":"/etc/passwd"}}},"process":{"audit_token":{"pid":1},"executable":{"path":"/bin/sh"}}}`)
	_, ok := ParseESLoggerLine(line, []Target{{Path: "/tmp/x"}})
	if ok {
		t.Fatal("should not match")
	}
}

func TestParseESLoggerUnlink(t *testing.T) {
	line := []byte(`{"event":{"unlink":{"target":{"path":"/Users/a/canary"}}},"process":{"audit_token":{"pid":9},"executable":{"path":"/bin/rm"}}}`)
	touch, ok := ParseESLoggerLine(line, []Target{{Path: "/Users/a/canary"}})
	if !ok || touch.Action != "delete" {
		t.Fatalf("got ok=%v action=%s", ok, touch.Action)
	}
}
