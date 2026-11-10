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
	Letter      string
	Color       string
	Key         string
}

type launcherPage struct {
	Email   string
	Tools   []tile
	Apps    []tile
	Search  bool
	Warning bool
}

func (l *Launcher) url(name string) string {
	return "https://" + name + "." + l.domain + "/"
}

// build works out what this person sees. A source that can't be trusted shows nothing from that
// source and a warning, never something it might not have meant.
func (l *Launcher) build(email string) launcherPage {
	page := launcherPage{Email: email}
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
					Icon: template.HTML(toolIcons[tool.Icon]), IconName: tool.Icon, Key: strings.ToLower(tool.Title + " " + tool.Description + " " + tool.Name),
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
			Title: entry.Name, Description: "Published app", URL: l.url(entry.Name),
			Letter: strings.ToUpper(entry.Name[:1]), Color: colorFor(entry.Name), Key: entry.Name,
		})
	}

	page.Warning = len(problems) > 0
	page.Search = len(page.Tools)+len(page.Apps) > 9
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
	header.Set("Cache-Control", "no-store")
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

// Icons are fixed SVG drawn in the binary; the launcher file only picks one by name.
var toolIcons = map[string]string{
	"vault":   `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15.5" r="1.6"/></svg>`,
	"files":   `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7.5A2.5 2.5 0 0 1 5.5 5H10l2 2.5h6.5A2.5 2.5 0 0 1 21 10v7.5a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z"/></svg>`,
	"browser": `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/></svg>`,
	"app":     `<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="6.5" height="6.5" rx="1.5"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.5"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.5"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.5"/></svg>`,
	"chart":   `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20V4M4 20h16"/><path d="M8 16v-4M12 16V8M16 16v-6"/></svg>`,
	"chat":    `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5v8a2.5 2.5 0 0 1-2.5 2.5H10l-4.5 3.5V17h0A2.5 2.5 0 0 1 4 14.5z"/></svg>`,
}

const launcherCSS = `
:root{color-scheme:dark;--bg:#0f1115;--panel:#171a21;--line:#262a33;--text:#e8eaef;--muted:#9aa1ad;--focus:#7aa2ff}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:40px 16px 64px}
header{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:8px 16px;margin-bottom:28px}
h1{font-size:26px;font-weight:650;margin:0;letter-spacing:-.01em}
.who{color:var(--muted);font-size:13px;overflow-wrap:anywhere}
h2{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:28px 0 12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:14px}
.tile{display:flex;flex-direction:column;align-items:center;text-align:center;gap:10px;padding:20px 12px 16px;border:1px solid var(--line);border-radius:18px;background:var(--panel);color:inherit;text-decoration:none;transition:transform .12s ease,border-color .12s ease,background .12s ease}
.tile:hover{transform:translateY(-2px);border-color:#3a4050;background:#1b1f27}
.tile:focus-visible{outline:2px solid var(--focus);outline-offset:3px}
.tile[hidden],section[hidden]{display:none}
.icon{width:64px;height:64px;border-radius:16px;display:grid;place-items:center;font-size:28px;font-weight:650;color:#fff;box-shadow:inset 0 1px 0 rgba(255,255,255,.18)}
.icon svg{width:32px;height:32px;fill:none;stroke:#fff;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.i-vault{background:linear-gradient(145deg,#f59e0b,#b45309)}
.i-files{background:linear-gradient(145deg,#3b82f6,#1d4ed8)}
.i-browser{background:linear-gradient(145deg,#14b8a6,#0f766e)}
.i-app,.i-chart,.i-chat{background:linear-gradient(145deg,#8b5cf6,#6d28d9)}
.c0{background:linear-gradient(145deg,#ef4444,#b91c1c)}.c1{background:linear-gradient(145deg,#f97316,#c2410c)}
.c2{background:linear-gradient(145deg,#eab308,#a16207)}.c3{background:linear-gradient(145deg,#22c55e,#15803d)}
.c4{background:linear-gradient(145deg,#06b6d4,#0e7490)}.c5{background:linear-gradient(145deg,#6366f1,#4338ca)}
.c6{background:linear-gradient(145deg,#d946ef,#a21caf)}.c7{background:linear-gradient(145deg,#ec4899,#be185d)}
.name{font-weight:600;font-size:15px;overflow-wrap:anywhere}
.desc{color:var(--muted);font-size:12.5px;line-height:1.35;overflow-wrap:anywhere}
.search{width:100%;max-width:360px;padding:10px 14px;border-radius:12px;border:1px solid var(--line);background:var(--panel);color:var(--text);font:inherit}
.search:focus{outline:2px solid var(--focus);outline-offset:1px}
.empty,.warn{color:var(--muted);padding:32px 0;text-align:center}
.warn{padding:10px 14px;border:1px solid #5b4a1f;background:#221d10;color:#e9d39a;border-radius:12px;text-align:left;margin-bottom:8px}
@media (max-width:420px){.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.tile{padding:16px 8px 12px}main{padding-top:28px}}
`

const launcherJS = `
(function(){var q=document.getElementById("q");if(!q)return;q.addEventListener("input",function(){var v=q.value.trim().toLowerCase();document.querySelectorAll(".tile").forEach(function(t){t.hidden=!!v&&t.getAttribute("data-k").indexOf(v)<0});document.querySelectorAll("section").forEach(function(s){s.hidden=!s.querySelector(".tile:not([hidden])")})})})();
`

const launcherHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Apps</title>
<style>` + launcherCSS + `</style>
</head>
<body>
<main>
<header><h1>Apps</h1><span class="who">Signed in as {{.Email}}</span></header>
{{if .Warning}}<p class="warn">Some shortcuts could not be loaded. The owner has been told in the server log.</p>{{end}}
{{if .Search}}<input id="q" class="search" type="search" placeholder="Search" aria-label="Search apps" autocomplete="off">{{end}}
{{if .Tools}}<section><h2>Tools</h2><div class="grid">{{range .Tools}}
<a class="tile" href="{{.URL}}" data-k="{{.Key}}"><span class="icon i-{{.IconName}}">{{.Icon}}</span><span class="name">{{.Title}}</span>{{if .Description}}<span class="desc">{{.Description}}</span>{{end}}</a>{{end}}
</div></section>{{end}}
{{if .Apps}}<section><h2>Your apps</h2><div class="grid">{{range .Apps}}
<a class="tile" href="{{.URL}}" data-k="{{.Key}}"><span class="icon {{.Color}}">{{.Letter}}</span><span class="name">{{.Title}}</span><span class="desc">{{.Description}}</span></a>{{end}}
</div></section>{{end}}
{{if not (or .Tools .Apps)}}<p class="empty">Nothing here for you yet.</p>{{end}}
</main>
<script>` + launcherJS + `</script>
</body>
</html>
`
