//go:build windows

package sensor

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hardenPrivateFile restricts NTFS ACL to the owner, the current process user,
// SYSTEM, and Administrators (matching package-agent install.ps1 intent), then
// verifies no broad Allow ACEs remain. If WRITE_DAC is unavailable, accept an
// already-private ACL instead of failing startup.
func hardenPrivateFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("%s: expected a file", path)
	}
	return hardenPrivatePath(path, false)
}

func hardenPrivateDir(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s: expected a directory", path)
	}
	return hardenPrivatePath(path, true)
}

func hardenPrivatePath(path string, isDir bool) error {
	if err := setPrivateACL(path, isDir); err != nil {
		// No WRITE_DAC (or similar): fail closed only if the existing ACL is broad.
		if err2 := rejectBroadAllowACL(path); err2 == nil {
			return nil
		} else {
			return fmt.Errorf("%s: set private ACL: %w; existing ACL not private: %v", path, err, err2)
		}
	}
	if err := rejectBroadAllowACL(path); err != nil {
		hint := "restrict NTFS ACL to owner/current-user/SYSTEM/Administrators"
		if isDir {
			return fmt.Errorf("%s: %w; %s", path, err, hint)
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func setPrivateACL(path string, isDir bool) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil {
		return fmt.Errorf("no owner SID")
	}
	selfSID, err := currentProcessUserSID()
	if err != nil {
		return err
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}

	var inherit uint32 = windows.NO_INHERITANCE
	if isDir {
		// New children under data_dir should stay private.
		inherit = windows.CONTAINER_INHERIT_ACE | windows.OBJECT_INHERIT_ACE
	}

	entries := uniqueGrants(inherit, owner, selfSID, systemSID, adminSID)
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	// PROTECTED_DACL disables inherited ACEs from parent directories (e.g. Users on %%TEMP%%).
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
	if err != nil {
		return err
	}
	return nil
}

func uniqueGrants(inherit uint32, sids ...*windows.SID) []windows.EXPLICIT_ACCESS {
	out := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	seen := make([]*windows.SID, 0, len(sids))
	for _, sid := range sids {
		if sid == nil {
			continue
		}
		already := false
		for _, s := range seen {
			if s.Equals(sid) {
				already = true
				break
			}
		}
		if already {
			continue
		}
		seen = append(seen, sid)
		out = append(out, explicitGrant(sid, inherit))
	}
	return out
}

func currentProcessUserSID() (*windows.SID, error) {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	if tu.User.Sid == nil {
		return nil, errors.New("no process user SID")
	}
	return tu.User.Sid.Copy()
}

func explicitGrant(sid *windows.SID, inherit uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func rejectBroadAllowACL(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("missing DACL")
	}

	broad, err := broadSIDs()
	if err != nil {
		return err
	}

	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, b := range broad {
			if b.Equals(sid) {
				return fmt.Errorf("ACL grants access to %s", b.String())
			}
		}
	}
	return nil
}

func broadSIDs() ([]*windows.SID, error) {
	types := []windows.WELL_KNOWN_SID_TYPE{
		windows.WinWorldSid,
		windows.WinAuthenticatedUserSid,
		windows.WinBuiltinUsersSid,
	}
	out := make([]*windows.SID, 0, len(types))
	for _, t := range types {
		sid, err := windows.CreateWellKnownSid(t)
		if err != nil {
			return nil, err
		}
		out = append(out, sid)
	}
	return out, nil
}
