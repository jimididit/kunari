package forge

import "testing"

func TestMaterializeDirRejectsEscape(t *testing.T) {
	out := t.TempDir()
	_, err := materializeDir(out, &Artifact{
		DirName:  "..",
		DirFiles: map[string][]byte{"x": []byte("y")},
	})
	if err == nil {
		t.Fatal("expected reject for DirName=..")
	}
	_, err = materializeDir(out, &Artifact{
		DirName:  "ok",
		DirFiles: map[string][]byte{"../x": []byte("y")},
	})
	if err == nil {
		t.Fatal("expected reject for relative escape entry")
	}
}
