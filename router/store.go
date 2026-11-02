package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
)

const (
	maxEmailChars = 254
	maxEntryBytes = 256 << 10
	maxTeamBytes  = 256 << 10
)

var (
	appNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	emailRE   = regexp.MustCompile(`^[a-z0-9_%+-]+(\.[a-z0-9_%+-]+)*@([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])$`)
)

// normalizeEmail is the one normalisation: ASCII only, then lower-cased. Refusing non-ASCII first
// matters: Unicode lower-casing turns the Kelvin sign into a plain k. The gatekeeper and the
// plugin apply the same rule, and tests/email_vectors.json keeps all three in step.
func normalizeEmail(value string) (string, bool) {
	if len(value) == 0 || len(value) > maxEmailChars {
		return "", false
	}
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return "", false
		}
	}
	lowered := strings.ToLower(value)
	if !emailRE.MatchString(lowered) {
		return "", false
	}
	return lowered, true
}

func validAppName(name string) bool {
	return appNameRE.MatchString(name) && !strings.HasSuffix(name, "-") && !strings.Contains(name, "--")
}

// Entry is one app in the root-owned registry the gatekeeper writes.
type Entry struct {
	Name      string   `json:"name"`
	Port      int      `json:"port"`
	CreatedBy string   `json:"created_by"`
	CreatedAt string   `json:"created_at"`
	Guests    []string `json:"guests"`
}

// Store reads the registry and the team file on every check. They are small, and with no cache
// an edit applies to the next request with no restart and no way to go stale.
type Store struct {
	registryDir string
	teamFile    string
	portMin     int
	portMax     int
	trustedUID  int // the owner both must have; root in production

	mu          sync.Mutex
	lastBadTeam string
}

func newStore(config *Config) *Store {
	return &Store{registryDir: config.RegistryDir, teamFile: config.TeamFile,
		portMin: config.PortMin, portMax: config.PortMax, trustedUID: 0}
}

func (s *Store) checkTrusted(info os.FileInfo, label string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", label)
	}
	if int(stat.Uid) != s.trustedUID {
		return fmt.Errorf("%s: owned by uid %d, not %d", label, stat.Uid, s.trustedUID)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: writable by group or others", label)
	}
	return nil
}

// readTrusted reads a file without following a link or blocking, and refuses one that someone
// other than its trusted owner could have changed.
func (s *Store) readTrusted(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if err := s.checkTrusted(info, path); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	return data, nil
}

// App returns the registry entry, nil if there is none, or an error if it cannot be trusted.
func (s *Store) App(name string) (*Entry, error) {
	if !validAppName(name) {
		return nil, nil
	}
	info, err := os.Lstat(s.registryDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", s.registryDir)
	}
	if err := s.checkTrusted(info, s.registryDir); err != nil {
		return nil, err
	}
	data, err := s.readTrusted(filepath.Join(s.registryDir, name+".json"), maxEntryBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var entry Entry
	if err := decoder.Decode(&entry); err != nil {
		return nil, fmt.Errorf("registry entry %s: %w", name, err)
	}
	if entry.Name != name {
		return nil, fmt.Errorf("registry entry %s: name does not match", name)
	}
	if entry.Port < s.portMin || entry.Port > s.portMax {
		return nil, fmt.Errorf("registry entry %s: port outside the app range", name)
	}
	for _, guest := range entry.Guests {
		if normal, ok := normalizeEmail(guest); !ok || normal != guest {
			return nil, fmt.Errorf("registry entry %s: invalid guest address", name)
		}
	}
	return &entry, nil
}

// Team returns the team's addresses. A line that isn't an address grants nothing: it is skipped
// and logged, so one typo doesn't lock the whole team out.
func (s *Store) Team() (map[string]bool, []string, error) {
	data, err := s.readTrusted(s.teamFile, maxTeamBytes)
	if err != nil {
		return nil, nil, err
	}
	team := make(map[string]bool)
	var bad []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if email, ok := normalizeEmail(line); ok {
			team[email] = true
		} else {
			bad = append(bad, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	s.logBadTeamLines(bad)
	return team, bad, nil
}

func (s *Store) logBadTeamLines(bad []string) {
	joined := strings.Join(bad, "\n")
	s.mu.Lock()
	defer s.mu.Unlock()
	if joined != s.lastBadTeam {
		s.lastBadTeam = joined
		if len(bad) > 0 {
			log.Printf("team file: ignoring %d lines that are not addresses: %q", len(bad), bad)
		}
	}
}
