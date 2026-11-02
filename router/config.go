package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	audRE    = regexp.MustCompile(`^[0-9a-f]{32,128}$`)
)

// Config is the router's settings file. Unknown keys are refused, so a typo cannot silently
// leave a check at its default.
type Config struct {
	Listen         string `json:"listen"`
	Domain         string `json:"domain"`
	TeamDomain     string `json:"team_domain"`
	AUD            string `json:"aud"`
	TeamFile       string `json:"team_file"`
	RegistryDir    string `json:"registry_dir"`
	PortMin        int    `json:"port_min"`
	PortMax        int    `json:"port_max"`
	RecheckSeconds int    `json:"recheck_seconds"`
}

func loadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	config := &Config{PortMin: 3000, PortMax: 3999, RecheckSeconds: 30}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return config, nil
}

func (c *Config) validate() error {
	if !domainRE.MatchString(c.Domain) {
		return errors.New("domain must be a lower-case hostname with at least two labels")
	}
	if !domainRE.MatchString(c.TeamDomain) || !strings.HasSuffix(c.TeamDomain, ".cloudflareaccess.com") {
		return errors.New("team_domain must look like <team>.cloudflareaccess.com")
	}
	if !audRE.MatchString(c.AUD) {
		return errors.New("aud must be the Access application's audience tag")
	}
	if c.TeamFile == "" || c.RegistryDir == "" {
		return errors.New("team_file and registry_dir are required")
	}
	if c.PortMin < 1024 || c.PortMax > 65535 || c.PortMin > c.PortMax {
		return errors.New("port_min and port_max are not a sensible range")
	}
	if c.RecheckSeconds < 1 {
		return errors.New("recheck_seconds must be at least 1")
	}
	host, portText, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return errors.New("listen must be a loopback address: the tunnel is the only way in")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("listen has an invalid port")
	}
	if port >= c.PortMin && port <= c.PortMax {
		return errors.New("listen port must be outside the app port range, which the agent user can reach")
	}
	return nil
}

func (c *Config) recheckInterval() time.Duration {
	return time.Duration(c.RecheckSeconds) * time.Second
}

func (c *Config) issuer() string {
	return "https://" + c.TeamDomain
}

func (c *Config) certsURL() string {
	return c.issuer() + "/cdn-cgi/access/certs"
}
