package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// The launcher is one page on a reserved hostname (for example apps.<domain>) that lists, for the
// signed-in person, the fixed tools they may open and the published apps they can reach. It only
// links: each tool keeps its own Access application, and each app is still checked by authorize.
//
// Two root-owned sources feed it, read on every request like the team file and the registry:
// the launcher file (fixed tools, edited by hand) and the registry (written by the gatekeeper).
// Nothing the AI can write reaches the page.

const (
	maxLauncherBytes = 64 << 10
	maxTools         = 50
	maxGroupEmails   = 200
	maxTitleChars    = 40
	maxDescChars     = 100
	teamGroup        = "team" // built-in group: the addresses in the team file
)

var groupNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// LauncherFile is the hand-edited list of fixed tools. Unknown keys are refused.
type LauncherFile struct {
	Groups map[string][]string `json:"groups"`
	Tools  []LauncherTool      `json:"tools"`
}

// LauncherTool is one fixed tile. Its address is always https://<name>.<domain>/, so a tile can't
// point anywhere else.
type LauncherTool struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Icon        string   `json:"icon"`
	VisibleTo   []string `json:"visible_to"`
}

func plainText(value string, limit int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > limit {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == ' ' || r == ' ' || unicode.Is(unicode.Bidi_Control, r) {
			return false
		}
	}
	return true
}

func (l *LauncherFile) validate(host string) error {
	if len(l.Tools) > maxTools {
		return fmt.Errorf("more than %d tools", maxTools)
	}
	for group, emails := range l.Groups {
		if !groupNameRE.MatchString(group) || group == teamGroup {
			return fmt.Errorf("group %q: name must match %s and not be %q", group, groupNameRE, teamGroup)
		}
		if len(emails) > maxGroupEmails {
			return fmt.Errorf("group %q: more than %d addresses", group, maxGroupEmails)
		}
		for _, email := range emails {
			if normal, ok := normalizeEmail(email); !ok || normal != email {
				return fmt.Errorf("group %q: invalid or not lower-case address", group)
			}
		}
	}
	seen := map[string]bool{}
	for i, tool := range l.Tools {
		label := fmt.Sprintf("tool %d (%q)", i+1, tool.Name)
		if !validAppName(tool.Name) {
			return fmt.Errorf("%s: name must be a single hostname label", label)
		}
		if tool.Name == host {
			return fmt.Errorf("%s: name is the launcher's own hostname", label)
		}
		if seen[tool.Name] {
			return fmt.Errorf("%s: listed twice", label)
		}
		seen[tool.Name] = true
		if strings.TrimSpace(tool.Title) == "" || !plainText(tool.Title, maxTitleChars) {
			return fmt.Errorf("%s: title must be 1-%d characters of plain text", label, maxTitleChars)
		}
		if !plainText(tool.Description, maxDescChars) {
			return fmt.Errorf("%s: description must be at most %d characters of plain text", label, maxDescChars)
		}
		if _, ok := toolIcons[tool.Icon]; !ok {
			return fmt.Errorf("%s: unknown icon %q", label, tool.Icon)
		}
		if len(tool.VisibleTo) == 0 {
			return fmt.Errorf("%s: visible_to is empty, so nobody would see it", label)
		}
		for _, group := range tool.VisibleTo {
			if _, ok := l.Groups[group]; !ok && group != teamGroup {
				return fmt.Errorf("%s: unknown group %q", label, group)
			}
		}
	}
	return nil
}

// Launcher builds and serves the page.
type Launcher struct {
	host   string
	file   string
	domain string
	store  *Store

	mu      sync.Mutex
	lastErr string
}

func newLauncher(config *Config, store *Store) *Launcher {
	if config.LauncherHost == "" {
		return nil
	}
	return &Launcher{host: config.LauncherHost, file: config.LauncherFile, domain: config.Domain, store: store}
}

// Load reads and checks the launcher file.
func (l *Launcher) Load() (*LauncherFile, error) {
	data, err := l.store.readTrusted(l.file, maxLauncherBytes)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var file LauncherFile
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("%s: %w", l.file, err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%s: trailing data after the JSON object", l.file)
	}
	if err := file.validate(l.host); err != nil {
		return nil, fmt.Errorf("%s: %w", l.file, err)
	}
	return &file, nil
}

// logOnce reports a problem when it first appears or changes, not on every page view.
func (l *Launcher) logOnce(message string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if message != l.lastErr {
		l.lastErr = message
		if message != "" {
			log.Print(message)
		}
	}
}

type tile struct {
	Title       string
	Description string
	URL         string
	Icon        template.HTML // only ever one of the constants in toolIcons
	IconName    string
	Host        string
	Letter      string
	Color       string
	Key         string
}

type launcherPage struct {
	Email   string
	Initial string
	Domain  string
	Tools   []tile
	Apps    []tile
	Total   int
	Warning bool
}

func (l *Launcher) url(name string) string {
	return "https://" + name + "." + l.domain + "/"
}

// build works out what this person sees. A source that can't be trusted shows nothing from that
// source and a warning, never something it might not have meant.
func (l *Launcher) build(email string) launcherPage {
	page := launcherPage{Email: email, Initial: strings.ToUpper(email[:1]), Domain: l.domain}
	var problems []string

	team, _, err := l.store.Team()
	if err != nil {
		problems = append(problems, fmt.Sprintf("launcher: cannot trust the team file: %v", err))
		team = map[string]bool{}
	}

	if file, err := l.Load(); err != nil {
		problems = append(problems, fmt.Sprintf("launcher: cannot use the launcher file: %v", err))
	} else {
		for _, tool := range file.Tools {
			if visibleTo(tool.VisibleTo, file.Groups, team, email) {
				page.Tools = append(page.Tools, tile{
					Title: tool.Title, Description: tool.Description, URL: l.url(tool.Name),
					Icon: template.HTML(toolIcons[tool.Icon]), IconName: tool.Icon, Host: tool.Name + "." + l.domain, Key: strings.ToLower(tool.Title + " " + tool.Description + " " + tool.Name),
				})
			}
		}
	}

	entries, err := l.store.Apps()
	if err != nil {
		problems = append(problems, fmt.Sprintf("launcher: cannot trust the registry: %v", err))
	}
	for _, entry := range entries {
		if entry.Name == l.host || !(team[email] || contains(entry.Guests, email)) {
			continue
		}
		page.Apps = append(page.Apps, tile{
			Title: entry.Name, Description: "Published app", URL: l.url(entry.Name), Host: entry.Name + "." + l.domain,
			Letter: strings.ToUpper(entry.Name[:1]), Color: colorFor(entry.Name), Key: entry.Name,
		})
	}

	page.Warning = len(problems) > 0
	page.Total = len(page.Tools) + len(page.Apps)
	l.logOnce(strings.Join(problems, "; "))
	return page
}

func visibleTo(groups []string, defined map[string][]string, team map[string]bool, email string) bool {
	for _, group := range groups {
		if group == teamGroup {
			if team[email] {
				return true
			}
			continue
		}
		if contains(defined[group], email) {
			return true
		}
	}
	return false
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func colorFor(name string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return fmt.Sprintf("c%d", h.Sum32()%8)
}

func (l *Launcher) ServeHTTP(w http.ResponseWriter, request *http.Request, email string) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		deny(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if request.URL.Path != "/" || request.URL.RawQuery != "" {
		deny(w, http.StatusNotFound, "Not found")
		return
	}
	page := l.build(email)
	log.Printf("launcher email=%q tools=%d apps=%d", email, len(page.Tools), len(page.Apps))
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	// no-transform keeps Cloudflare from rewriting the page: its email obfuscation would replace
	// the signed-in address with "[email protected]" and a decoder script the CSP blocks.
	header.Set("Cache-Control", "no-store, no-transform")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("X-Robots-Tag", "noindex, nofollow")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", launcherCSP)
	w.WriteHeader(http.StatusOK)
	if err := launcherTemplate.Execute(w, page); err != nil {
		log.Printf("launcher: render: %v", err)
	}
}

// Apps lists the published apps the router can trust. A broken entry is skipped and reported.
func (s *Store) Apps() ([]*Entry, error) {
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
	dir, err := os.ReadDir(s.registryDir)
	if err != nil {
		return nil, err
	}
	var entries []*Entry
	var problems []error
	for _, item := range dir {
		name, found := strings.CutSuffix(item.Name(), ".json")
		if !found || !validAppName(name) {
			continue
		}
		entry, err := s.App(name)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		if entry != nil {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, errors.Join(problems...)
}

func cspHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

var (
	launcherCSP = "default-src 'none'; style-src " + cspHash(launcherCSS) + "; script-src " + cspHash(launcherJS) +
		"; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	launcherTemplate = template.Must(template.New("launcher").Parse(launcherHTML))
)

// Icons are fixed SVG drawn in the binary; the launcher file only picks one by name. They inherit
// the glyph's colour through currentColor.
var toolIcons = map[string]string{
	"vault":   `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><path d="M12 14.5v2"/></svg>`,
	"files":   `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3.5 8A2.5 2.5 0 0 1 6 5.5h3.6a2 2 0 0 1 1.5.7l1.1 1.3H18A2.5 2.5 0 0 1 20.5 10v7.5A2.5 2.5 0 0 1 18 20H6a2.5 2.5 0 0 1-2.5-2.5z"/><path d="M3.5 10.5h17"/></svg>`,
	"browser": `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4.5" width="18" height="15" rx="2.5"/><path d="M3 9h18"/><path d="M6.5 6.75h.01M9 6.75h.01"/></svg>`,
	"app":     `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="6.5" height="6.5" rx="1.8"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.8"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.8"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.8"/></svg>`,
	"chart":   `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 4v16h16"/><path d="M8 15l3.5-4 3 2.5L19 8"/></svg>`,
	"chat":    `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 12a7.5 7.5 0 0 1-11 6.6L4 20l1.4-4.6A7.5 7.5 0 1 1 20 12z"/></svg>`,
}

const launcherCSS = `
:root{color-scheme:dark;--bg:#141d24;--surface:#20292f;--surface-2:#283136;--border:rgba(255,255,255,.08);--border-2:rgba(255,255,255,.14);--text:rgba(255,255,255,.9);--text-2:rgba(255,255,255,.62);--text-3:rgba(255,255,255,.42);--accent:#2196f3;--ring:rgba(33,150,243,.32);--glow:rgba(33,150,243,.07);--topbar:rgba(40,49,54,.9);--sh-1:0 1px 2px hsl(0deg 0% 0% / .07),0 2px 4px hsl(0deg 0% 0% / .06);--sh-2:0 1px 2px hsl(0deg 0% 0% / .1),0 18px 40px -18px rgba(0,0,0,.65);--warn-bg:#3a2f16;--warn-border:rgba(245,158,11,.3);--warn-text:#f8d58a}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;background:var(--bg) radial-gradient(1100px 420px at 50% -180px,var(--glow),transparent 72%) no-repeat;color:var(--text);font:14px/1.5 Roboto,-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
a{color:inherit;-webkit-tap-highlight-color:transparent}
svg{display:block}
.sr-only{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
.topbar{position:sticky;top:0;z-index:10;background:var(--topbar);-webkit-backdrop-filter:saturate(180%) blur(14px);backdrop-filter:saturate(180%) blur(14px);border-bottom:1px solid var(--border)}
.topbar-in{max-width:1120px;height:56px;margin:0 auto;padding:0 24px;display:flex;align-items:center;gap:12px}
.brand{display:flex;align-items:center;gap:10px;font-size:15px;font-weight:600;letter-spacing:-.01em;text-decoration:none}
.mark{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;background:linear-gradient(135deg,#4f46e5 0%,#7c3aed 55%,#db2777 100%);box-shadow:inset 0 1px 0 rgba(255,255,255,.28),0 1px 2px rgba(16,24,40,.25)}
.mark svg{width:15px;height:15px;fill:#fff}
.divider{width:1px;height:18px;background:var(--border-2);transform:rotate(18deg)}
.domain{color:var(--text-3);font-size:14px;white-space:nowrap}
.spacer{flex:1}
.account{display:flex;align-items:center;gap:12px;min-width:0}
.who{display:flex;align-items:center;gap:10px;min-width:0}
.email{color:var(--text-2);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:280px}
.avatar{width:30px;height:30px;flex:none;border-radius:50%;display:grid;place-items:center;font-size:12.5px;font-weight:600;color:#fff;background:linear-gradient(135deg,#0ea5e9,#6366f1);box-shadow:0 0 0 2px var(--surface),0 0 0 3px var(--border-2)}
.signout{flex:none;height:32px;display:inline-flex;align-items:center;padding:0 12px;border-radius:8px;border:1px solid var(--border-2);background:var(--surface);box-shadow:var(--sh-1);color:var(--text-2);font-size:13px;font-weight:500;text-decoration:none;transition:color .15s,border-color .15s,background .15s}
.signout:hover{color:var(--text);background:var(--surface-2)}
.signout:focus-visible{outline:none;box-shadow:0 0 0 3px var(--ring);border-color:var(--accent)}
main{width:100%;max-width:1120px;margin:0 auto;padding:56px 24px 72px;flex:1}
.hero{display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:20px 32px;margin-bottom:40px}
h1{margin:0;font-size:32px;line-height:1.15;font-weight:650;letter-spacing:-.028em}
.lede{margin:8px 0 0;color:var(--text-2);font-size:15px}
.search{position:relative;display:block;width:min(100%,360px)}
.search svg{position:absolute;left:13px;top:50%;width:16px;height:16px;transform:translateY(-50%);fill:none;stroke:var(--text-3);stroke-width:2;stroke-linecap:round;pointer-events:none}
.search input{width:100%;height:42px;padding:0 48px 0 40px;border-radius:11px;border:1px solid var(--border-2);background:var(--surface);box-shadow:var(--sh-1);color:var(--text);font:inherit;font-size:14px;-webkit-appearance:none;appearance:none;transition:border-color .15s,box-shadow .15s}
.search input::placeholder{color:var(--text-3)}
.search input::-webkit-search-cancel-button{-webkit-appearance:none}
.search input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 4px var(--ring)}
.search kbd{position:absolute;right:11px;top:50%;transform:translateY(-50%);min-width:22px;height:22px;display:grid;place-items:center;padding:0 6px;border-radius:6px;border:1px solid var(--border-2);border-bottom-width:2px;background:var(--surface-2);color:var(--text-3);font:500 11.5px/1 ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace}
.search input:focus~kbd{opacity:0}
.alert{display:flex;gap:12px;align-items:flex-start;margin:0 0 32px;padding:12px 16px;border-radius:12px;border:1px solid var(--warn-border);background:var(--warn-bg);color:var(--warn-text);font-size:13.5px}
.alert svg{width:18px;height:18px;flex:none;margin-top:1px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.alert strong{font-weight:600}
section+section{margin-top:44px}
.sec-head{display:flex;align-items:center;gap:10px;margin:0 0 16px}
h2{margin:0;font-size:15px;font-weight:600;letter-spacing:-.01em}
.count{min-width:22px;height:20px;display:inline-grid;place-items:center;padding:0 7px;border-radius:999px;border:1px solid var(--border);background:var(--surface-2);color:var(--text-2);font-size:11.5px;font-weight:500;font-variant-numeric:tabular-nums}
.sec-note{margin-left:auto;color:var(--text-3);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:16px}
.card{position:relative;display:flex;flex-direction:column;min-height:176px;padding:20px;border-radius:16px;border:1px solid var(--border);background:var(--surface);box-shadow:var(--sh-1);text-decoration:none;outline:none;transition:transform .2s cubic-bezier(.2,.7,.2,1),box-shadow .2s,border-color .2s}
.card:hover{transform:translateY(-2px);border-color:var(--border-2);box-shadow:var(--sh-2)}
.card:active{transform:translateY(0);transition-duration:.06s}
.card:focus-visible{border-color:var(--accent);box-shadow:0 0 0 4px var(--ring)}
.card[hidden],section[hidden],.empty[hidden]{display:none}
.glyph{width:46px;height:46px;flex:none;border-radius:13px;display:grid;place-items:center;margin-bottom:18px;color:#fff;font-size:19px;font-weight:650;letter-spacing:-.02em;box-shadow:inset 0 1px 0 rgba(255,255,255,.3),inset 0 -1px 0 rgba(0,0,0,.1),0 1px 2px rgba(16,24,40,.14),0 6px 14px -6px rgba(16,24,40,.35)}
.glyph svg{width:23px;height:23px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.body{display:flex;flex-direction:column;min-width:0}
.title{font-size:15.5px;font-weight:600;letter-spacing:-.012em;color:var(--text);overflow-wrap:anywhere}
.desc{margin-top:4px;color:var(--text-2);font-size:13.5px;line-height:1.45}
.host{margin-top:auto;padding-top:18px;color:var(--text-3);font:12px/1 ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.go{position:absolute;top:20px;right:20px;width:28px;height:28px;border-radius:8px;display:grid;place-items:center;color:var(--text-3);opacity:0;transform:translate(-4px,4px);transition:opacity .2s,transform .2s cubic-bezier(.2,.7,.2,1),background .2s,color .2s}
.go svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.card:hover .go,.card:focus-visible .go{opacity:1;transform:none;color:var(--text);background:var(--surface-2)}
.g-vault{background:linear-gradient(155deg,#fbbf24,#ea580c)}
.g-files{background:linear-gradient(155deg,#60a5fa,#2563eb)}
.g-browser{background:linear-gradient(155deg,#34d399,#0d9488)}
.g-app{background:linear-gradient(155deg,#a78bfa,#6d28d9)}
.g-chart{background:linear-gradient(155deg,#818cf8,#4338ca)}
.g-chat{background:linear-gradient(155deg,#f472b6,#be185d)}
.c0{background:linear-gradient(155deg,#fb7185,#e11d48)}.c1{background:linear-gradient(155deg,#fb923c,#ea580c)}
.c2{background:linear-gradient(155deg,#facc15,#ca8a04)}.c3{background:linear-gradient(155deg,#4ade80,#16a34a)}
.c4{background:linear-gradient(155deg,#22d3ee,#0891b2)}.c5{background:linear-gradient(155deg,#818cf8,#4f46e5)}
.c6{background:linear-gradient(155deg,#e879f9,#a21caf)}.c7{background:linear-gradient(155deg,#94a3b8,#475569)}
.empty{display:flex;flex-direction:column;align-items:center;text-align:center;padding:72px 24px;border:1px dashed var(--border-2);border-radius:18px}
.empty .glyph{margin-bottom:16px;background:var(--surface-2);color:var(--text-3);border:1px solid var(--border);box-shadow:var(--sh-1)}
.empty h2{font-size:16px}
.empty p{max-width:380px;margin:6px 0 0;color:var(--text-2)}
.term{color:var(--text);font-weight:500}
footer{width:100%;max-width:1120px;margin:0 auto;padding:0 24px 36px;display:flex;align-items:center;gap:8px;color:var(--text-3);font-size:12.5px}
footer svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
@media (max-width:720px){.email,.divider,.domain{display:none}}
@media (max-width:640px){
.topbar-in{padding:0 16px;height:52px}
main{padding:28px 16px 56px}
h1{font-size:26px}
.lede{font-size:14px}
.hero{gap:18px;margin-bottom:28px}
.search{width:100%}
.search kbd{display:none}
.search input{padding-right:14px}
section+section{margin-top:32px}
.sec-note{display:none}
.grid{grid-template-columns:1fr;gap:10px}
.card{flex-direction:row;align-items:center;gap:14px;min-height:0;padding:14px 14px 14px 16px;border-radius:14px}
.card:hover{transform:none}
.glyph{width:42px;height:42px;border-radius:12px;margin:0}
.glyph svg{width:21px;height:21px}
.body{flex:1}
.title{font-size:15px}
.desc{margin-top:1px;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.host{display:none}
.go{position:static;opacity:1;transform:none;width:24px;height:24px;color:var(--text-3);background:none}
.card:hover .go,.card:focus-visible .go{background:none}
.empty{padding:48px 20px}
footer{padding:0 16px 28px}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important}}
`

const launcherJS = `
(function(){var h=new Date().getHours(),g=document.getElementById("greet");if(g){g.textContent=h<5?"Good evening":h<12?"Good morning":h<18?"Good afternoon":"Good evening"}var q=document.getElementById("q");if(!q)return;var cards=[].slice.call(document.querySelectorAll(".card")),secs=[].slice.call(document.querySelectorAll("section")),none=document.getElementById("none"),term=document.getElementById("term");function run(){var v=q.value.trim().toLowerCase(),n=0;cards.forEach(function(c){var m=!v||c.getAttribute("data-k").indexOf(v)>=0;c.hidden=!m;if(m)n++});secs.forEach(function(s){s.hidden=!s.querySelector(".card:not([hidden])")});none.hidden=n>0;term.textContent=q.value.trim()}q.addEventListener("input",run);q.addEventListener("keydown",function(e){if(e.key==="Escape"){q.value="";run();q.blur()}else if(e.key==="Enter"){var f=cards.filter(function(c){return!c.hidden})[0];if(f){e.preventDefault();window.open(f.href,"_blank","noopener")}}});document.addEventListener("keydown",function(e){var t=e.target&&e.target.tagName;if((e.key==="/"&&t!=="INPUT"&&t!=="TEXTAREA")||((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==="k")){e.preventDefault();q.focus();q.select()}})})();
`

const arrowIcon = `<span class="go" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M7 17 17 7M9 7h8v8"/></svg></span>`

const launcherHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#283136">
<title>Apps · {{.Domain}}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%236d4aed'/%3E%3Cg fill='%23fff'%3E%3Crect x='8' y='8' width='7' height='7' rx='2'/%3E%3Crect x='17' y='8' width='7' height='7' rx='2'/%3E%3Crect x='8' y='17' width='7' height='7' rx='2'/%3E%3Crect x='17' y='17' width='7' height='7' rx='2'/%3E%3C/g%3E%3C/svg%3E">
<style>` + launcherCSS + `</style>
</head>
<body>
<header class="topbar"><div class="topbar-in">
<a class="brand" href="/"><span class="mark"><svg viewBox="0 0 16 16" aria-hidden="true"><rect x="1" y="1" width="6" height="6" rx="1.6"/><rect x="9" y="1" width="6" height="6" rx="1.6"/><rect x="1" y="9" width="6" height="6" rx="1.6"/><rect x="9" y="9" width="6" height="6" rx="1.6"/></svg></span>Apps</a>
<span class="divider" aria-hidden="true"></span><span class="domain">{{.Domain}}</span>
<span class="spacer"></span>
<div class="account"><span class="who"><span class="sr-only">Signed in as</span><span class="email" title="{{.Email}}">{{.Email}}</span><span class="avatar" aria-hidden="true" title="{{.Email}}">{{.Initial}}</span></span><a class="signout" href="/cdn-cgi/access/logout">Sign out</a></div>
</div></header>
<main>
<div class="hero"><div><h1 id="greet">Welcome back</h1><p class="lede">Everything you can open, in one place.</p></div>
{{if .Total}}<label class="search"><span class="sr-only">Search apps and tools</span><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg><input id="q" type="search" placeholder="Search apps and tools" autocomplete="off" spellcheck="false" enterkeyhint="go"><kbd aria-hidden="true">/</kbd></label>{{end}}
</div>
{{if .Warning}}<div class="alert" role="status"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 2.5 20h19z"/><path d="M12 10v4M12 17h.01"/></svg><div><strong>Some shortcuts could not be loaded.</strong> Everything else is shown below; the details are in the server log.</div></div>{{end}}
{{if .Tools}}<section aria-labelledby="h-tools"><div class="sec-head"><h2 id="h-tools">Tools</h2><span class="count">{{len .Tools}}</span></div><div class="grid">{{range .Tools}}
<a class="card" href="{{.URL}}" target="_blank" rel="noopener" data-k="{{.Key}}"><span class="glyph g-{{.IconName}}">{{.Icon}}</span><span class="body"><span class="title">{{.Title}}</span>{{if .Description}}<span class="desc">{{.Description}}</span>{{end}}</span><span class="host">{{.Host}}</span>` + arrowIcon + `</a>{{end}}
</div></section>{{end}}
{{if .Apps}}<section aria-labelledby="h-apps"><div class="sec-head"><h2 id="h-apps">Apps</h2><span class="count">{{len .Apps}}</span><span class="sec-note">Built and published with Hermes</span></div><div class="grid">{{range .Apps}}
<a class="card" href="{{.URL}}" target="_blank" rel="noopener" data-k="{{.Key}}"><span class="glyph {{.Color}}">{{.Letter}}</span><span class="body"><span class="title">{{.Title}}</span><span class="desc">{{.Description}}</span></span><span class="host">{{.Host}}</span>` + arrowIcon + `</a>{{end}}
</div></section>{{end}}
{{if .Total}}<div class="empty" id="none" hidden><span class="glyph"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg></span><h2>No matches</h2><p>Nothing matches “<span class="term" id="term"></span>”. Try another name.</p></div>
{{else}}<div class="empty"><span class="glyph">` + `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="6.5" height="6.5" rx="1.8"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.8"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.8"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.8"/></svg>` + `</span><h2>No apps yet</h2><p>When someone shares an app with you, it will show up here.</p></div>{{end}}
</main>
<footer><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>Protected by Cloudflare Access</footer>
<script>` + launcherJS + `</script>
</body>
</html>
`
