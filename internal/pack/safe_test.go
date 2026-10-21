package pack

import "testing"

func TestNormalizeBinName(t *testing.T) {
	got, err := normalizeBinName("linux", "")
	if err != nil || got != "kunari" {
		t.Fatalf("default linux: %q %v", got, err)
	}
	got, err = normalizeBinName("windows", "AcmeWatch")
	if err != nil || got != "AcmeWatch.exe" {
		t.Fatalf("windows suffix: %q %v", got, err)
	}
	if _, err := normalizeBinName("linux", "svchost"); err == nil {
		t.Fatal("expected deny svchost")
	}
	if _, err := normalizeBinName("windows", "LSASS.EXE"); err == nil {
		t.Fatal("expected deny lsass.exe")
	}
	if _, err := normalizeBinName("linux", "tripwire.exe"); err == nil {
		t.Fatal("unix must reject .exe suffix")
	}
	if _, err := normalizeBinName("linux", "../evil"); err == nil {
		t.Fatal("expected path reject")
	}
}

func TestNormalizeUnitName(t *testing.T) {
	got, err := normalizeUnitName("linux", "")
	if err != nil || got != "kunari-sentinel" {
		t.Fatalf("default: %q %v", got, err)
	}
	got, err = normalizeUnitName("linux", "acme-watch.service")
	if err != nil || got != "acme-watch" {
		t.Fatalf("strip .service: %q %v", got, err)
	}
	if _, err := normalizeUnitName("linux", "sshd"); err == nil {
		t.Fatal("expected deny sshd")
	}
	if _, err := normalizeUnitName("darwin", "shortname"); err == nil {
		t.Fatal("darwin requires reverse-DNS")
	}
	got, err = normalizeUnitName("darwin", "com.acme.tripwire")
	if err != nil || got != "com.acme.tripwire" {
		t.Fatalf("darwin ok: %q %v", got, err)
	}
	if _, err := normalizeUnitName("windows", "svchost"); err == nil {
		t.Fatal("expected deny windows unit svchost")
	}
}
