package event

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	kcrypto "github.com/jimididit/kunari/internal/crypto"
	"github.com/jimididit/kunari/internal/safepath"
)

const genesisPrev = "0"

// Chain is an append-only, hash-chained, Ed25519-signed event log.
type Chain struct {
	mu       sync.Mutex
	path     string
	keys     *kcrypto.KeyPair
	seq      uint64
	prevHash string
}

func Open(path string, keys *kcrypto.KeyPair) (*Chain, error) {
	path, err := safepath.Clean(path)
	if err != nil {
		return nil, err
	}
	c := &Chain{path: path, keys: keys, prevHash: genesisPrev}
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o600) // path cleaned by safepath.Clean
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("corrupt event log: %w", err)
		}
		c.seq = ev.Integrity.Seq
		c.prevHash = ev.Integrity.Hash
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Chain) Append(ev *Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := ev.Validate(); err != nil {
		return err
	}
	c.seq++
	ev.Integrity.Seq = c.seq
	ev.Integrity.PrevHash = c.prevHash

	payload, err := ev.CanonicalPayload()
	if err != nil {
		return err
	}
	h := sha256.Sum256(append([]byte(ev.Integrity.PrevHash+"|"), payload...))
	ev.Integrity.Hash = hex.EncodeToString(h[:])
	sig := c.keys.Sign([]byte(ev.Integrity.Hash))
	ev.Integrity.Sig = hex.EncodeToString(sig)

	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // c.path cleaned at Open
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	c.prevHash = ev.Integrity.Hash
	return nil
}

// VerifyFile checks chain continuity and signatures.
func VerifyFile(path string, pub ed25519.PublicKey) error {
	path, err := safepath.Clean(path)
	if err != nil {
		return err
	}
	f, err := os.Open(path) // path cleaned by safepath.Clean
	if err != nil {
		return err
	}
	defer f.Close()
	return VerifyReader(f, pub)
}

func VerifyReader(r io.Reader, pub ed25519.PublicKey) error {
	sc := bufio.NewScanner(r)
	prev := genesisPrev
	var expectSeq uint64
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return fmt.Errorf("invalid json: %w", err)
		}
		expectSeq++
		if ev.Integrity.Seq != expectSeq {
			return fmt.Errorf("sequence gap: got %d want %d", ev.Integrity.Seq, expectSeq)
		}
		if ev.Integrity.PrevHash != prev {
			return fmt.Errorf("prev_hash mismatch at seq %d", ev.Integrity.Seq)
		}
		payload, err := ev.CanonicalPayload()
		if err != nil {
			return err
		}
		h := sha256.Sum256(append([]byte(ev.Integrity.PrevHash+"|"), payload...))
		want := hex.EncodeToString(h[:])
		if ev.Integrity.Hash != want {
			return fmt.Errorf("hash mismatch at seq %d", ev.Integrity.Seq)
		}
		sig, err := hex.DecodeString(ev.Integrity.Sig)
		if err != nil {
			return fmt.Errorf("bad signature encoding at seq %d", ev.Integrity.Seq)
		}
		if !kcrypto.Verify(pub, []byte(ev.Integrity.Hash), sig) {
			return fmt.Errorf("bad signature at seq %d", ev.Integrity.Seq)
		}
		prev = ev.Integrity.Hash
	}
	return sc.Err()
}
