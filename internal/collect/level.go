package collect

import "fmt"

// Level controls how much actor/network context is retained.
type Level string

const (
	Minimal  Level = "minimal"
	Standard Level = "standard"
	Forensic Level = "forensic"
)

func Parse(s string) (Level, error) {
	switch Level(s) {
	case Minimal, Standard, Forensic:
		return Level(s), nil
	default:
		return "", fmt.Errorf("invalid collection level %q (want minimal|standard|forensic)", s)
	}
}

func (l Level) AllowsForensicNetwork() bool {
	return l == Forensic
}
