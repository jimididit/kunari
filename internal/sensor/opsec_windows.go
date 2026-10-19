//go:build windows

package sensor

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hardenPrivateFile restricts NTFS ACL to the owner, SYSTEM, and Administrators
// (matching package-agent install.ps1), then verifies no broad Allow ACEs remain.
func hardenPrivateFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("%s: expected a file", path)
	}
	if err := setPrivateACL(path, false); err != nil {
		return fmt.Errorf("%s: set private ACL: %w", path, err)
	}
	if err := rejectBroadAllowACL(path); err != nil {
		return fmt.Errorf("%s: %w", path, err)
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
	if err := setPrivateACL(path, true); err != nil {
		return fmt.Errorf("%s: set private ACL: %w", path, err)
	}
	if err := rejectBroadAllowACL(path); err != nil {
		return fmt.Errorf("%s: %w; restrict NTFS ACL to owner/SYSTEM/Administrators", path, err)
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

	entries := []windows.EXPLICIT_ACCESS{
		explicitGrant(owner, inherit),
		explicitGrant(systemSID, inherit),
		explicitGrant(adminSID, inherit),
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	// PROTECTED_DACL disables inherited ACEs from parent directories (e.g. Users on %%TEMP%%).
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
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
