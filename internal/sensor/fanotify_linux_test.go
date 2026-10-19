//go:build linux

package sensor

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestMapFanMaskPrefersSpecificBits(t *testing.T) {
	cases := []struct {
		mask uint64
		want string
	}{
		{unix.FAN_OPEN, "open"},
		{unix.FAN_ACCESS, "read"},
		{unix.FAN_MODIFY, "modify"},
		{unix.FAN_CLOSE_WRITE, "modify"},
		{unix.FAN_OPEN_EXEC, "exec"},
		{unix.FAN_OPEN | unix.FAN_ACCESS, "read"},
		{unix.FAN_OPEN | unix.FAN_MODIFY, "modify"},
		{unix.FAN_OPEN | unix.FAN_ACCESS | unix.FAN_MODIFY, "modify"},
	}
	for _, tc := range cases {
		if got := mapFanMask(tc.mask); got != tc.want {
			t.Fatalf("mask=%#x got %q want %q", tc.mask, got, tc.want)
		}
	}
}
