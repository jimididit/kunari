//go:build windows

package sensor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestHardenPrivateFileWindowsACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinel.json")
	if err := os.WriteFile(path, []byte(`{"targets":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := hardenPrivateFile(path); err != nil {
		t.Fatal(err)
	}
	if err := rejectBroadAllowACL(path); err != nil {
		t.Fatal(err)
	}
	self, err := currentProcessUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if !aclAllowsSID(path, self) {
		t.Fatal("hardened ACL must grant the current process user (dedicated service account)")
	}
}

func aclAllowsSID(path string, want *windows.SID) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil || ace == nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if want.Equals(sid) {
			return true
		}
	}
	return false
}

func TestHardenPrivateDirWindowsACL(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := hardenPrivateDir(data); err != nil {
		t.Fatal(err)
	}
	if err := rejectBroadAllowACL(data); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigHardensWindowsACL(t *testing.T) {
	dir := t.TempDir()
	decoy := filepath.Join(dir, "decoy.env")
	if err := os.WriteFile(decoy, []byte("x=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "sentinel.json")
	body := []byte(fmt.Sprintf(
		`{"targets":[{"Path":%s,"TokenID":"abcdabcdabcdabcd"}],"data_dir":%s,"heartbeat_every":"60s"}`,
		strconv.Quote(decoy), strconv.Quote(dataDir),
	))
	if err := os.WriteFile(cfgPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := rejectBroadAllowACL(cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := rejectBroadAllowACL(dataDir); err != nil {
		t.Fatal(err)
	}
}
