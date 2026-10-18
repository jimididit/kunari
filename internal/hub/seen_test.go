package hub

import "testing"

func TestSeenReserveForgetAllowsRetry(t *testing.T) {
	s := newSeenIDs(64)
	if s.Reserve("a") {
		t.Fatal("first reserve should be new")
	}
	if !s.Reserve("a") {
		t.Fatal("second reserve should be duplicate")
	}
	s.Forget("a")
	if s.Reserve("a") {
		t.Fatal("after Forget, reserve should succeed again")
	}
}
