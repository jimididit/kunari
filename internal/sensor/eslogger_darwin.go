//go:build darwin

package sensor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type esloggerWatcher struct {
	targets []Target
	hash    string
	cmd     *exec.Cmd
}

func newESLogger(targets []Target) (*esloggerWatcher, error) {
	if _, err := exec.LookPath("eslogger"); err != nil {
		return nil, fmt.Errorf("eslogger not found: %w", err)
	}
	// Fail open so OpenBest can fall back to FSEvents when unprivileged.
	probe := exec.Command("eslogger", "--list-events")
	if outb, err := probe.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("eslogger probe: %w (%s)", err, truncate(string(outb), 160))
	}
	var parts []string
	for _, t := range targets {
		if _, err := os.Stat(t.Path); err != nil {
			return nil, fmt.Errorf("stat %s: %w", t.Path, err)
		}
		parts = append(parts, t.Path+"|"+t.TokenID)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ";") + "|mac-eslogger"))
	return &esloggerWatcher{targets: targets, hash: hex.EncodeToString(sum[:])}, nil
}

func (w *esloggerWatcher) Tier() Tier { return TierMacESLogger }
func (w *esloggerWatcher) Capabilities() string {
	return "open/write/unlink/rename/create via eslogger (ES notify); needs root+FDA; no dedicated read event"
}
func (w *esloggerWatcher) ConfigHash() string { return w.hash }
func (w *esloggerWatcher) Close() error {
	if w.cmd != nil && w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
	}
	return nil
}

func (w *esloggerWatcher) Run(ctx context.Context, out chan<- Touch) error {
	// Fixed argv only (no user-controlled args). Event names are ES notify types.
	cmd := exec.CommandContext(ctx, "eslogger", "open", "write", "unlink", "rename", "create", "exec")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("eslogger start: %w", err)
	}
	w.cmd = cmd

	errCh := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			// Surface early privilege errors
			line := sc.Text()
			if strings.Contains(strings.ToLower(line), "permission") || strings.Contains(strings.ToLower(line), "tcc") {
				errCh <- fmt.Errorf("eslogger: %s", line)
				return
			}
		}
	}()

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return nil
		case err := <-errCh:
			_ = cmd.Process.Kill()
			return err
		default:
		}
		if touch, ok := ParseESLoggerLine(sc.Bytes(), w.targets); ok {
			select {
			case out <- touch:
			case <-ctx.Done():
				_ = cmd.Process.Kill()
				return nil
			}
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return err
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return waitErr
}
