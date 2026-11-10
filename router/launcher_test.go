package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testLauncher = `{
  "groups": {"admins": ["owner@gmail.com", "admin@gmail.com"]},
  "tools": [
    {"name": "vault", "title": "Vault", "description": "Site logins", "icon": "vault", "visible_to": ["admins"]},
    {"name": "files", "title": "Files", "description": "Workspace files", "icon": "files", "visible_to": ["admins"]},
    {"name": "browser", "title": "Browser", "description": "Shared browser", "icon": "browser", "visible_to": ["admins"]},
    {"name": "wiki", "title": "Wiki", "description": "", "icon": "app", "visible_to": ["team"]}
  ]
}`

// newLauncherFixture is a router with the launcher on apps.<domain>.
func newLauncherFixture(t *testing.T, launcher string) *fixture {
	t.Helper()
	f := newFixture(t)
	f.config.LauncherHost = "apps"
	f.config.LauncherFile = filepath.Join(f.dir, "launcher.json")
	if launcher != "" {
		f.writeFile(f.config.LauncherFile, launcher, 0o640)
	}
	f.server.Close()
	f.server = httptest.NewServer(newRouter(f.config, f.verifier, f.store))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fixture) launcherPage(token string) (int, http.Header, string) {
	f.t.Helper()
	request, _ := http.NewRequest(http.MethodGet, f.server.URL+"/", nil)
	request.Host = host("apps")
	if token != "" {
		request.Header.Set(tokenHeader, token)
	}
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, response.Header, string(body)
}

func hasTile(body, name string) bool {
	return strings.Contains(body, `href="https://`+name+`.`+testDomain+`/"`)
}

func TestLauncherShowsEachPersonOnlyTheirTiles(t *testing.T) {
	f := newLauncherFixture(t, testLauncher)
	f.writeTeam(ownerEmail + "\n" + bobEmail + "\n")
	f.publish("app-a", f.nameApp("a"), aliceEmail)
	f.publish("app-b", f.nameApp("b"))

	cases := []struct {
		email string
		want  []string
		not   []string
	}{
		{ownerEmail, []string{"vault", "files", "browser", "wiki", "app-a", "app-b"}, nil},
		{"admin@gmail.com", []string{"vault", "files", "browser"}, []string{"wiki", "app-a", "app-b"}},
		{bobEmail, []string{"wiki", "app-a", "app-b"}, []string{"vault", "files", "browser"}},
		{aliceEmail, []string{"app-a"}, []string{"vault", "files", "browser", "wiki", "app-b"}},
		{"stranger@gmail.com", nil, []string{"vault", "files", "browser", "wiki", "app-a", "app-b"}},
	}
	for _, c := range cases {
		t.Run(c.email, func(t *testing.T) {
			status, _, body := f.launcherPage(tokenFor(c.email))
			if status != 200 {
				t.Fatalf("status %d", status)
			}
			for _, name := range c.want {
				if !hasTile(body, name) {
					t.Errorf("missing tile %s", name)
				}
			}
			for _, name := range c.not {
				if hasTile(body, name) {
					t.Errorf("unexpected tile %s", name)
				}
			}
			if !strings.Contains(body, "Signed in as "+c.email) {
				t.Error("signed-in email not shown")
			}
			if c.want == nil && !strings.Contains(body, "Nothing here for you yet") {
				t.Error("empty message not shown")
			}
		})
	}
	t.Run("email compares case-insensitively", func(t *testing.T) {
		_, _, body := f.launcherPage(tokenFor("OWNER@Gmail.com"))
		if !hasTile(body, "vault") {
			t.Error("owner in mixed case lost the vault tile")
		}
	})
}

func TestLauncherNeedsAValidToken(t *testing.T) {
	f := newLauncherFixture(t, testLauncher)
	_, other := keys()
	for name, token := range map[string]string{
		"none":    "",
		"forged":  sign(other, goodHeader(), goodClaims(ownerEmail)),
		"garbage": "abc.def.ghi",
	} {
		t.Run(name, func(t *testing.T) {
			status, _, body := f.launcherPage(token)
			if status != 401 || strings.Contains(body, "vault") {
				t.Fatalf("got %d %q", status, body)
			}
		})
	}
}

func TestLauncherHeadersAndMethods(t *testing.T) {
	f := newLauncherFixture(t, testLauncher)
	status, header, body := f.launcherPage(tokenFor(ownerEmail))
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	for key, want := range map[string]string{
		"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Frame-Options": "DENY",
		"X-Content-Type-Options": "nosniff", "X-Robots-Tag": "noindex, nofollow", "Referrer-Policy": "no-referrer",
	} {
		if got := header.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	csp := header.Get("Content-Security-Policy")
	for _, part := range []string{"default-src 'none'", "frame-ancestors 'none'", "script-src 'sha256-", "style-src 'sha256-"} {
		if !strings.Contains(csp, part) {
			t.Errorf("CSP lacks %q: %s", part, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Error("CSP allows unsafe-inline")
	}
	// The hashes must match what the page actually carries, or the browser drops the style and script.
	if !strings.Contains(body, "<style>"+launcherCSS+"</style>") || !strings.Contains(body, "<script>"+launcherJS+"</script>") {
		t.Error("page style or script differs from the hashed constants")
	}
	for _, external := range []string{"http://", "src=\"http", "@import", "url("} {
		if strings.Contains(strings.ReplaceAll(body, "https://", ""), external) {
			t.Errorf("page loads something external: %q", external)
		}
	}

	token := tokenFor(ownerEmail)
	for _, c := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, "/", 405}, {http.MethodPut, "/", 405}, {http.MethodDelete, "/", 405},
		{http.MethodGet, "/other", 404}, {http.MethodGet, "/?x=1", 404}, {http.MethodHead, "/", 200},
	} {
		request, _ := http.NewRequest(c.method, f.server.URL+c.path, nil)
		request.Host = host("apps")
		request.Header.Set(tokenHeader, token)
		response, err := http.DefaultTransport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != c.status {
			t.Errorf("%s %s: got %d, want %d", c.method, c.path, response.StatusCode, c.status)
		}
	}
}

func TestLauncherEscapesNamesAndEmails(t *testing.T) {
	f := newLauncherFixture(t, `{"groups":{"g":["owner@gmail.com"]},"tools":[
		{"name":"vault","title":"<b>x</b>","description":"\"><script>alert(1)</script>","icon":"vault","visible_to":["g"]}]}`)
	_, _, body := f.launcherPage(tokenFor(ownerEmail))
	if strings.Contains(body, "<b>x</b>") || strings.Contains(body, "<script>alert") {
		t.Fatal("title or description reached the page unescaped")
	}
}

func TestLauncherRefusesBadFiles(t *testing.T) {
	bad := map[string]string{
		"unknown key":       `{"groups":{},"tools":[],"extra":1}`,
		"unknown icon":      `{"groups":{"g":["owner@gmail.com"]},"tools":[{"name":"vault","title":"V","description":"","icon":"https://x/y.svg","visible_to":["g"]}]}`,
		"name with a dot":   `{"groups":{"g":["owner@gmail.com"]},"tools":[{"name":"evil.com","title":"V","description":"","icon":"vault","visible_to":["g"]}]}`,
		"name with a slash": `{"groups":{"g":["owner@gmail.com"]},"tools":[{"name":"x/../y","title":"V","description":"","icon":"vault","visible_to":["g"]}]}`,
		"own hostname":      `{"groups":{"g":["owner@gmail.com"]},"tools":[{"name":"apps","title":"V","description":"","icon":"vault","visible_to":["g"]}]}`,
		"listed twice":      `{"groups":{"g":["owner@gmail.com"]},"tools":[{"name":"vault","title":"V","description":"","icon":"vault","visible_to":["g"]},{"name":"vault","title":"V","description":"","icon":"vault","visible_to":["g"]}]}`,
		"unknown group":     `{"groups":{},"tools":[{"name":"vault","title":"V","description":"","icon":"vault","visible_to":["nobody"]}]}`,
		"empty visible_to":  `{"groups":{},"tools":[{"name":"vault","title":"V","description":"","icon":"vault","visible_to":[]}]}`,
		"upper-case email":  `{"groups":{"g":["Owner@gmail.com"]},"tools":[]}`,
		"group named team":  `{"groups":{"team":["owner@gmail.com"]},"tools":[]}`,
		"empty title":       `{"groups":{"g":["owner@gmail.com"]},"tools":[{"name":"vault","title":" ","description":"","icon":"vault","visible_to":["g"]}]}`,
		"control char":      `{"groups":{"g":["owner@gmail.com"]},"tools":[{"name":"vault","title":"V‮","description":"","icon":"vault","visible_to":["g"]}]}`,
		"trailing data":     `{"groups":{},"tools":[]} {}`,
		"not json":          `nope`,
	}
	for name, text := range bad {
		t.Run(name, func(t *testing.T) {
			f := newLauncherFixture(t, text)
			if _, err := newLauncher(f.config, f.store).Load(); err == nil {
				t.Fatal("accepted")
			}
			status, _, body := f.launcherPage(tokenFor(ownerEmail))
			if status != 200 || !strings.Contains(body, "could not be loaded") || hasTile(body, "vault") {
				t.Fatalf("got %d, warning shown %v", status, strings.Contains(body, "could not be loaded"))
			}
		})
	}
}

func TestLauncherRefusesUntrustedFile(t *testing.T) {
	f := newLauncherFixture(t, testLauncher)
	if err := os.Chmod(f.config.LauncherFile, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := newLauncher(f.config, f.store).Load(); err == nil {
		t.Fatal("group-writable file accepted")
	}
	_, _, body := f.launcherPage(tokenFor(ownerEmail))
	if hasTile(body, "vault") || !strings.Contains(body, "could not be loaded") {
		t.Fatal("group-writable file used")
	}

	f2 := newLauncherFixture(t, "")
	target := filepath.Join(f2.dir, "real.json")
	f2.writeFile(target, testLauncher, 0o640)
	if err := os.Symlink(target, f2.config.LauncherFile); err != nil {
		t.Fatal(err)
	}
	if _, err := newLauncher(f2.config, f2.store).Load(); err == nil {
		t.Fatal("symlinked file accepted")
	}
	f3 := newLauncherFixture(t, "")
	if _, err := newLauncher(f3.config, f3.store).Load(); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestLauncherAppsFollowTheRegistry(t *testing.T) {
	f := newLauncherFixture(t, testLauncher)
	f.publish("app-a", f.nameApp("a"))
	_, _, body := f.launcherPage(tokenFor(ownerEmail))
	if !hasTile(body, "app-a") {
		t.Fatal("published app missing")
	}
	f.unpublish("app-a")
	_, _, body = f.launcherPage(tokenFor(ownerEmail))
	if hasTile(body, "app-a") {
		t.Fatal("unpublished app still shown")
	}
	t.Run("an app named like the launcher is never shown or reached", func(t *testing.T) {
		f.publish("apps", f.nameApp("impostor"))
		status, _, body := f.launcherPage(tokenFor(ownerEmail))
		if status != 200 || strings.Contains(body, "app:impostor") || hasTile(body, "apps") {
			t.Fatalf("got %d %q", status, body)
		}
	})
	t.Run("a broken entry hides only itself", func(t *testing.T) {
		f.publish("app-c", f.nameApp("c"))
		f.writeFile(filepath.Join(f.config.RegistryDir, "app-d.json"), "{broken", 0o640)
		_, _, body := f.launcherPage(tokenFor(ownerEmail))
		if !hasTile(body, "app-c") || hasTile(body, "app-d") || !strings.Contains(body, "could not be loaded") {
			t.Fatal("broken entry handled wrongly")
		}
	})
}

func TestLauncherSearchAppearsAboveNineTiles(t *testing.T) {
	f := newLauncherFixture(t, testLauncher)
	_, _, body := f.launcherPage(tokenFor(ownerEmail))
	if strings.Contains(body, `id="q"`) {
		t.Fatal("search shown with 4 tiles")
	}
	for _, name := range []string{"aa", "bb", "cc", "dd", "ee", "ff"} {
		f.publish("app-"+name, f.nameApp(name))
	}
	_, _, body = f.launcherPage(tokenFor(ownerEmail))
	if !strings.Contains(body, `id="q"`) {
		t.Fatal("search missing with 10 tiles")
	}
}

func TestOtherHostsUnchangedWithLauncher(t *testing.T) {
	f := newLauncherFixture(t, testLauncher)
	f.publish("app-a", f.nameApp("a"), aliceEmail)
	f.expect(host("app-a"), tokenFor(ownerEmail), 200, "app:a")
	f.expect(host("app-a"), tokenFor(aliceEmail), 200, "app:a")
	f.expect(host("app-a"), tokenFor("stranger@gmail.com"), 403, "")
	f.expect(host("vault"), tokenFor(ownerEmail), 404, "Not found")
	f.expect(host("apps"), "", 401, "Sign-in required")
}

func TestLauncherConfigValidation(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"host without file": func(c *Config) { c.LauncherHost = "apps" },
		"file without host": func(c *Config) { c.LauncherFile = "/x" },
		"dotted host":       func(c *Config) { c.LauncherHost = "a.b"; c.LauncherFile = "/x" },
	} {
		t.Run(name, func(t *testing.T) {
			config := testConfig(t.TempDir())
			config.PortMin, config.PortMax = 3000, 3999
			change(config)
			if err := config.validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	config := testConfig(t.TempDir())
	config.PortMin, config.PortMax = 3000, 3999
	config.LauncherHost, config.LauncherFile = "apps", "/etc/hermes-apps/launcher.json"
	if err := config.validate(); err != nil {
		t.Fatalf("good config refused: %v", err)
	}
}
