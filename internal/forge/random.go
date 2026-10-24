package forge

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randomPastTime() time.Time {
	days := randomInt(60) + 1
	hours := randomInt(24)
	secs := randomInt(3600)
	return time.Now().UTC().AddDate(0, 0, -days).Add(-time.Duration(hours)*time.Hour - time.Duration(secs)*time.Second)
}

func themeFiller(theme, name string) string {
	switch theme {
	case "finance":
		return fmt.Sprintf("# %s - finance working copy\n# Do not distribute outside finance.\n# Q%d budget export\n# contact: finance-ops@example.invalid\n", name, randomInt(4)+1)
	case "hr":
		return fmt.Sprintf("# %s - HR confidential\n# Working copy only\n# Employee ref: E-%04d\n", name, randomInt(9000)+1000)
	case "devops":
		return fmt.Sprintf("# %s\n# staging secrets - rotate after cutover\n# last reviewed: %s\n", name, randomPastTime().Format("2006-01-02"))
	case "it-admin":
		return fmt.Sprintf("# %s - IT admin notes\n# Jump host inventory draft\n# Ticket: IT-%d\n", name, randomInt(90000)+10000)
	default:
		return fmt.Sprintf("# %s\n# local env - do not commit\n# reviewed: %s\n", name, randomPastTime().Format("2006-01-02"))
	}
}

func randomPadding(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
	b := make([]byte, n)
	rb := randomBytes(n)
	for i := range b {
		b[i] = alphabet[int(rb[i])%len(alphabet)]
	}
	return string(b)
}

func u32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}
