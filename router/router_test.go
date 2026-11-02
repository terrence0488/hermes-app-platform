package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newRedirectServer(t *testing.T, target string) string {
	t.Helper()
	server := httptest.NewServer(http.RedirectHandler(target, http.StatusFound))
	t.Cleanup(server.Close)
	return server.URL
}

func host(app string) string { return app + "." + testDomain }

func TestAccessRules(t *testing.T) {
	f := newFixture(t)
	f.publish("app-a", f.nameApp("a"), aliceEmail)
	f.publish("app-b", f.nameApp("b"), bobEmail)

	t.Run("team reaches every app", func(t *testing.T) {
		f.expect(host("app-a"), tokenFor(ownerEmail), 200, "app:a")
		f.expect(host("app-b"), tokenFor(ownerEmail), 200, "app:b")
	})
	t.Run("guest reaches only their app", func(t *testing.T) {
		f.expect(host("app-a"), tokenFor(aliceEmail), 200, "app:a")
		f.expect(host("app-b"), tokenFor(aliceEmail), 403, "signed in as "+aliceEmail)
		f.expect(host("app-b"), tokenFor(bobEmail), 200, "app:b")
		f.expect(host("app-a"), tokenFor(bobEmail), 403, "")
	})
	t.Run("stranger gets 403", func(t *testing.T) {
		f.expect(host("app-a"), tokenFor("stranger@gmail.com"), 403, "")
	})
	t.Run("emails compare case-insensitively", func(t *testing.T) {
		f.expect(host("app-a"), tokenFor("ALICE@Gmail.COM"), 200, "app:a")
		f.expect(host("app-a"), tokenFor("OWNER@GMAIL.COM"), 200, "app:a")
	})
	t.Run("no lookalike address passes", func(t *testing.T) {
		f.expect(host("app-a"), tokenFor("alice@gmail.com.evil.com"), 403, "")
		f.expect(host("app-a"), tokenFor("alice+x@gmail.com"), 403, "")
	})
	t.Run("host in upper case and with a port", func(t *testing.T) {
		f.expect("APP-A."+strings.ToUpper(testDomain), tokenFor(aliceEmail), 200, "app:a")
		f.expect(host("app-a")+":443", tokenFor(aliceEmail), 200, "app:a")
	})
}

func TestUnknownHosts(t *testing.T) {
	f := newFixture(t)
	f.publish("app-a", f.nameApp("a"))
	token := tokenFor(ownerEmail)
	for _, value := range []string{
		host("nope"), testDomain, "app-a." + host("sub"), "other.example.org", "app-a.example.net.evil.com",
		"evilexample.net", "127.0.0.1:8790", "[::1]:80", host("..%2f"), host("-x"), host("x"), host("trail-"),
		host("xn--abc"), host("app_a"), host("app-a") + ".",
	} {
		t.Run(value, func(t *testing.T) {
			f.expect(value, token, 404, "Not found")
		})
	}
}

func TestMissingOrInvalidTokenIsRefusedBeforeAnythingElse(t *testing.T) {
	f := newFixture(t)
	f.publish("app-a", f.nameApp("a"))
	key, other := keys()
	_ = key
	for name, token := range map[string]string{
		"missing": "",
		"forged":  sign(other, goodHeader(), goodClaims(ownerEmail)),
		"expired": sign(key, goodHeader(), func() map[string]any {
			claims := goodClaims(ownerEmail)
			claims["exp"] = time.Now().Add(-time.Minute).Unix()
			return claims
		}()),
		"wrong audience": sign(key, goodHeader(), func() map[string]any {
			claims := goodClaims(ownerEmail)
			claims["aud"] = []string{"dashboard-app-audience"}
			return claims
		}()),
	} {
		t.Run(name, func(t *testing.T) {
			f.expect(host("app-a"), token, 401, "Sign-in required")
			f.expect(host("unknown"), token, 401, "Sign-in required") // no way to probe for names
		})
	}
}

func TestEmailHeaderAloneIsWorthNothing(t *testing.T) {
	f := newFixture(t)
	f.publish("app-a", f.nameApp("a"))
	spoof := map[string]string{"Cf-Access-Authenticated-User-Email": ownerEmail, "X-Hermes-App-User-Email": ownerEmail}
	if status, _ := f.get(host("app-a"), "", spoof); status != 401 {
		t.Fatalf("no token: got %d", status)
	}
	if status, _ := f.get(host("app-a"), tokenFor("stranger@gmail.com"), spoof); status != 403 {
		t.Fatalf("stranger with a forged header: got %d", status)
	}
}

func TestTwoTokenHeadersAreRefused(t *testing.T) {
	f := newFixture(t)
	f.publish("app-a", f.nameApp("a"))
	request, _ := http.NewRequest(http.MethodGet, f.server.URL, nil)
	request.Host = host("app-a")
	request.Header.Add(tokenHeader, tokenFor(ownerEmail))
	request.Header.Add(tokenHeader, tokenFor(ownerEmail))
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("got %d", response.StatusCode)
	}
}

func TestHeadersThatReachTheApp(t *testing.T) {
	f := newFixture(t)
	var seen http.Header
	var seenHost string
	port := f.upstream(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		seen, seenHost = request.Header.Clone(), request.Host
	}))
	f.publish("app-a", port, aliceEmail)
	status, _ := f.get(host("app-a"), tokenFor("ALICE@gmail.com"), map[string]string{
		"X-Hermes-App-User-Email":            ownerEmail,
		"X-Hermes-App-User-Role":             roleTeam,
		"X_Hermes_App_User_Email":            ownerEmail,
		"X-Hermes-App-Anything":              "forged",
		"Cf-Access-Authenticated-User-Email": ownerEmail,
		"X-Forwarded-User":                   ownerEmail,
		"X-Forwarded-Email":                  ownerEmail,
		"X_Forwarded_Email":                  ownerEmail,
		"Remote-User":                        ownerEmail,
		"Forwarded":                          "for=1.2.3.4",
		"X-Forwarded-For":                    "1.2.3.4",
		"X-Forwarded-Host":                   "evil.example.org",
		"Cf-Connecting-Ip":                   "203.0.113.7",
		"Cookie":                             "theme=dark; CF_Authorization=stolen; cf_binding=x; session=abc",
		"Authorization":                      "Bearer app-token",
	})
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	want := map[string]string{
		headerUserEmail: aliceEmail, headerUserRole: roleGuest, headerAppName: "app-a",
		"X-Forwarded-Host": host("app-a"), "X-Forwarded-Proto": "https", "X-Forwarded-For": "203.0.113.7",
		"Cookie": "theme=dark; session=abc", "Authorization": "Bearer app-token",
	}
	for key, value := range want {
		if got := strings.Join(seen.Values(key), ","); got != value {
			t.Errorf("%s = %q, want %q", key, got, value)
		}
	}
	if seenHost != host("app-a") {
		t.Errorf("Host %q", seenHost)
	}
	for key := range seen {
		normal := strings.ReplaceAll(strings.ToLower(key), "_", "-")
		if identityHeaders[normal] || strings.HasPrefix(normal, "cf-access-") {
			t.Errorf("%s reached the app", key)
		}
	}
	if len(seen.Values(tokenHeader)) != 0 {
		t.Error("the Access token reached the app")
	}
	for key := range seen {
		if strings.HasPrefix(strings.ToLower(key), "x_") {
			t.Errorf("%s reached the app", key)
		}
	}
	if got := seen.Get("X-Hermes-App-Anything"); got != "" {
		t.Errorf("forged header reached the app: %q", got)
	}
}

func TestAppCannotSetAccessOrWideCookies(t *testing.T) {
	f := newFixture(t)
	port := f.upstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "CF_Authorization=evil; Path=/; Domain="+testDomain)
		w.Header().Add("Set-Cookie", "session=abc; Domain=."+testDomain+"; Path=/; HttpOnly; domain=x")
		w.Header().Add("Set-Cookie", "theme=dark; Path=/; Secure")
	}))
	f.publish("app-a", port)
	request, _ := http.NewRequest(http.MethodGet, f.server.URL, nil)
	request.Host = host("app-a")
	request.Header.Set(tokenHeader, tokenFor(ownerEmail))
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	got := response.Header.Values("Set-Cookie")
	want := []string{"session=abc; Path=/; HttpOnly", "theme=dark; Path=/; Secure"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", got)
	}
}

func TestChangesApplyWithoutARestart(t *testing.T) {
	f := newFixture(t)
	port := f.nameApp("a")
	alice := tokenFor(aliceEmail)
	f.expect(host("app-a"), alice, 404, "")
	f.publish("app-a", port)
	f.expect(host("app-a"), alice, 403, "")
	f.publish("app-a", port, aliceEmail)
	f.expect(host("app-a"), alice, 200, "app:a")
	f.publish("app-a", port)
	f.expect(host("app-a"), alice, 403, "")
	f.writeTeam(ownerEmail + "\n" + strings.ToUpper(aliceEmail) + "\n")
	f.expect(host("app-a"), alice, 200, "app:a")
	f.writeTeam(ownerEmail + "\n")
	f.expect(host("app-a"), alice, 403, "")
	f.unpublish("app-a")
	f.expect(host("app-a"), tokenFor(ownerEmail), 404, "")
}

func TestTeamFileFormat(t *testing.T) {
	f := newFixture(t)
	f.publish("app-a", f.nameApp("a"))
	f.writeTeam("# the team\n\n  " + aliceEmail + "  \n*@gmail.com\n@gmail.com\nbob@gmail.com, carol@gmail.com\n# dave@gmail.com\n")
	f.expect(host("app-a"), tokenFor(aliceEmail), 200, "app:a")
	for _, email := range []string{bobEmail, "carol@gmail.com", "dave@gmail.com", "anyone@gmail.com"} {
		f.expect(host("app-a"), tokenFor(email), 403, "")
	}
}

func TestRefusesWhatItCannotConfirm(t *testing.T) {
	f := newFixture(t)
	port := f.nameApp("a")
	owner := tokenFor(ownerEmail)
	entryPath := filepath.Join(f.config.RegistryDir, "app-a.json")
	reset := func() {
		_ = os.Remove(entryPath)
		f.publish("app-a", port)
		f.writeTeam(ownerEmail + "\n")
		_ = os.Chmod(f.config.RegistryDir, 0o750)
		f.expect(host("app-a"), owner, 200, "app:a")
	}
	reset()
	entry := func(text string) { f.writeFile(entryPath, text, 0o640) }
	cases := map[string]func(){
		"entry not JSON":   func() { entry("{oops") },
		"entry wrong name": func() { entry(`{"name":"other","port":3001,"created_by":"x","created_at":"y","guests":[]}`) },
		"entry unknown field": func() {
			entry(`{"name":"app-a","port":3001,"created_by":"x","created_at":"y","guests":[],"team":true}`)
		},
		"entry bad guest":        func() { entry(`{"name":"app-a","port":3001,"created_by":"x","created_at":"y","guests":["NOPE"]}`) },
		"entry port too low":     func() { entry(`{"name":"app-a","port":80,"created_by":"x","created_at":"y","guests":[]}`) },
		"entry port too high":    func() { entry(`{"name":"app-a","port":70000,"created_by":"x","created_at":"y","guests":[]}`) },
		"entry world writable":   func() { _ = os.Chmod(entryPath, 0o666) },
		"entry is a symlink":     func() { _ = os.Remove(entryPath); _ = os.Symlink(f.config.TeamFile, entryPath) },
		"entry is a directory":   func() { _ = os.Remove(entryPath); _ = os.Mkdir(entryPath, 0o750) },
		"team file missing":      func() { _ = os.Remove(f.config.TeamFile) },
		"team file writable":     func() { _ = os.Chmod(f.config.TeamFile, 0o664) },
		"team file is a symlink": func() { _ = os.Remove(f.config.TeamFile); _ = os.Symlink(entryPath, f.config.TeamFile) },
		"registry dir writable":  func() { _ = os.Chmod(f.config.RegistryDir, 0o777) },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			breakIt()
			f.expect(host("app-a"), owner, 503, "Service unavailable")
			_ = os.RemoveAll(entryPath)
			reset()
		})
	}
	t.Run("files of another owner", func(t *testing.T) {
		f.store.trustedUID = os.Getuid() + 1
		defer func() { f.store.trustedUID = os.Getuid() }()
		f.expect(host("app-a"), owner, 503, "Service unavailable")
	})
}

func TestUpstreamDownGivesPlainBadGateway(t *testing.T) {
	f := newFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	f.publish("app-a", port)
	status, body := f.get(host("app-a"), tokenFor(ownerEmail), nil)
	if status != 502 || strings.Contains(body, "127.0.0.1") || strings.Contains(body, "connect") {
		t.Fatalf("%d %q", status, body)
	}
}

// rawRequest sends exact bytes, for requests a Go client refuses to produce.
func rawRequest(t *testing.T, address, text string) string {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, text); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func TestOddRequests(t *testing.T) {
	f := newFixture(t)
	f.publish("app-a", f.nameApp("a"), aliceEmail)
	f.publish("app-b", f.nameApp("b"))
	address := strings.TrimPrefix(f.server.URL, "http://")
	token := tokenFor(aliceEmail)
	cases := map[string]struct{ text, want string }{
		"CONNECT":        {"CONNECT 127.0.0.1:22 HTTP/1.1\r\nHost: " + host("app-a") + "\r\nCf-Access-Jwt-Assertion: " + token + "\r\n\r\n", "405"},
		"TRACE":          {"TRACE / HTTP/1.1\r\nHost: " + host("app-a") + "\r\nCf-Access-Jwt-Assertion: " + token + "\r\n\r\n", "405"},
		"two Host lines": {"GET / HTTP/1.1\r\nHost: " + host("app-a") + "\r\nHost: " + host("app-b") + "\r\nCf-Access-Jwt-Assertion: " + token + "\r\n\r\n", "400"},
		// The absolute form decides the host for both the check and the route, so it can't get past the check.
		"absolute URI aimed at another app": {"GET http://" + host("app-b") + "/ HTTP/1.1\r\nHost: " + host("app-a") + "\r\nCf-Access-Jwt-Assertion: " + token + "\r\n\r\n", "403"},
		"no Host":                           {"GET / HTTP/1.1\r\nCf-Access-Jwt-Assertion: " + token + "\r\n\r\n", "400"},
		"HTTP/1.0 no Host":                  {"GET / HTTP/1.0\r\nCf-Access-Jwt-Assertion: " + token + "\r\n\r\n", "404"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			line := rawRequest(t, address, testCase.text)
			if !strings.Contains(line, " "+testCase.want+" ") {
				t.Fatalf("got %q, want %s", line, testCase.want)
			}
		})
	}
}

func TestPathAndQueryAndBodyPassThrough(t *testing.T) {
	f := newFixture(t)
	port := f.upstream(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		_ = json.NewEncoder(w).Encode([]string{request.Method, request.URL.RequestURI(), string(body)})
	}))
	f.publish("app-a", port)
	request, _ := http.NewRequest(http.MethodPost, f.server.URL+"/a/b%20c?x=1&y=2", strings.NewReader("payload"))
	request.Host = host("app-a")
	request.Header.Set(tokenHeader, tokenFor(ownerEmail))
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var got []string
	_ = json.NewDecoder(response.Body).Decode(&got)
	if strings.Join(got, "|") != "POST|/a/b%20c?x=1&y=2|payload" {
		t.Fatalf("%q", got)
	}
}

func TestStreamingArrivesBeforeTheResponseEnds(t *testing.T) {
	f := newFixture(t)
	release := make(chan struct{})
	port := f.upstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprint(w, "data: second\n\n")
	}))
	f.publish("app-a", port)
	defer close(release)
	request, _ := http.NewRequest(http.MethodGet, f.server.URL, nil)
	request.Host = host("app-a")
	request.Header.Set(tokenHeader, tokenFor(ownerEmail))
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	line := make(chan string, 1)
	go func() {
		text, _ := bufio.NewReader(response.Body).ReadString('\n')
		line <- text
	}()
	select {
	case text := <-line:
		if text != "data: first\n" {
			t.Fatalf("%q", text)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the first event was held back")
	}
}

// With a known length and an ordinary type, only the proxy's own flush setting passes this on early.
func TestPartialBodyOfKnownLengthIsNotHeldBack(t *testing.T) {
	f := newFixture(t)
	release := make(chan struct{})
	port := f.upstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "12")
		fmt.Fprint(w, "first\n")
		w.(http.Flusher).Flush()
		<-release
		fmt.Fprint(w, "secon\n")
	}))
	f.publish("app-a", port)
	defer close(release)
	request, _ := http.NewRequest(http.MethodGet, f.server.URL, nil)
	request.Host = host("app-a")
	request.Header.Set(tokenHeader, tokenFor(ownerEmail))
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	line := make(chan string, 1)
	go func() {
		text, _ := bufio.NewReader(response.Body).ReadString('\n')
		line <- text
	}()
	select {
	case text := <-line:
		if text != "first\n" {
			t.Fatalf("%q", text)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the first part was held back")
	}
}

func TestAppNameParsing(t *testing.T) {
	router := &Router{domainSuffix: "." + testDomain}
	for value, want := range map[string]string{host("app-a"): "app-a", "APP-A.EXAMPLE.NET": "app-a", host("app-a") + ":443": "app-a"} {
		if got, ok := router.appName(value); !ok || got != want {
			t.Errorf("%q: got %q %v", value, got, ok)
		}
	}
	for _, value := range []string{testDomain, host("a.b"), host("-x"), host("x"), host("trail-"), host("xn--abc"), host("app_a"), "other.org", ""} {
		if got, ok := router.appName(value); ok {
			t.Errorf("%q accepted as %q", value, got)
		}
	}
}

func TestStreamIsCutWhenTheGuestIsRemoved(t *testing.T) {
	f := newFixture(t)
	done := make(chan struct{})
	defer close(done)
	port := f.upstream(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-request.Context().Done():
		case <-done:
		}
	}))
	f.publish("app-a", port, aliceEmail)
	request, _ := http.NewRequest(http.MethodGet, f.server.URL, nil)
	request.Host = host("app-a")
	request.Header.Set(tokenHeader, tokenFor(aliceEmail))
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	ended := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, response.Body)
		ended <- err
	}()
	f.publish("app-a", port)
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream outlived the guest's access")
	}
}

// --- A real RFC 6455 handshake and frames, on both sides of the router. ---

const webSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func webSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + webSocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func writeFrame(writer io.Writer, payload string, mask bool) error {
	first := []byte{0x81, byte(len(payload))}
	if !mask {
		_, err := writer.Write(append(first, payload...))
		return err
	}
	first[1] |= 0x80
	maskKey := []byte{1, 2, 3, 4}
	masked := []byte(payload)
	for i := range masked {
		masked[i] ^= maskKey[i%4]
	}
	_, err := writer.Write(append(append(first, maskKey...), masked...))
	return err
}

func readFrame(reader io.Reader) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", err
	}
	length := int(header[1] & 0x7f)
	if length >= 126 {
		return "", fmt.Errorf("long frames are not used here: %d", binary.BigEndian.Uint16(header))
	}
	var maskKey []byte
	if header[1]&0x80 != 0 {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(reader, maskKey); err != nil {
			return "", err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return "", err
	}
	for i := range payload {
		if maskKey != nil {
			payload[i] ^= maskKey[i%4]
		}
	}
	return string(payload), nil
}

// webSocketEcho is an app that echoes text frames and reports the identity the router told it.
func webSocketEcho(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "websocket only", http.StatusBadRequest)
			return
		}
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			webSocketAccept(request.Header.Get("Sec-WebSocket-Key")))
		_ = buffer.Flush()
		_ = writeFrame(conn, "user="+request.Header.Get(headerUserEmail), false)
		for {
			text, err := readFrame(buffer)
			if err != nil {
				return
			}
			if err := writeFrame(conn, "echo:"+text, false); err != nil {
				return
			}
		}
	})
}

type webSocketClient struct {
	conn   net.Conn
	reader *bufio.Reader
	status string
}

func dialWebSocket(t *testing.T, f *fixture, hostname, token string) *webSocketClient {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(f.server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n", hostname, key)
	if token != "" {
		fmt.Fprintf(conn, "%s: %s\r\n", tokenHeader, token)
	}
	fmt.Fprint(conn, "X-Hermes-App-User-Email: owner@gmail.com\r\n\r\n")
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	accept := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(name, "Sec-WebSocket-Accept") {
			accept = strings.TrimSpace(value)
		}
	}
	if strings.Contains(status, " 101 ") && accept != webSocketAccept(key) {
		t.Fatalf("bad accept header %q", accept)
	}
	return &webSocketClient{conn: conn, reader: reader, status: status}
}

func TestWebSocketRoundTrip(t *testing.T) {
	f := newFixture(t)
	f.publish("app-a", f.upstream(webSocketEcho(t)), aliceEmail)
	client := dialWebSocket(t, f, host("app-a"), tokenFor(aliceEmail))
	if !strings.Contains(client.status, " 101 ") {
		t.Fatalf("status %q", client.status)
	}
	identity, err := readFrame(client.reader)
	if err != nil {
		t.Fatal(err)
	}
	if identity != "user="+aliceEmail {
		t.Fatalf("the app was told %q: a client header got through", identity)
	}
	for _, text := range []string{"hello", "again"} {
		if err := writeFrame(client.conn, text, true); err != nil {
			t.Fatal(err)
		}
		reply, err := readFrame(client.reader)
		if err != nil {
			t.Fatal(err)
		}
		if reply != "echo:"+text {
			t.Fatalf("reply %q", reply)
		}
	}
}

func TestWebSocketIsCheckedLikeAnyOtherRequest(t *testing.T) {
	f := newFixture(t)
	f.publish("app-a", f.upstream(webSocketEcho(t)), aliceEmail)
	f.publish("app-b", f.upstream(webSocketEcho(t)))
	if client := dialWebSocket(t, f, host("app-a"), ""); !strings.Contains(client.status, " 401 ") {
		t.Fatalf("no token: %q", client.status)
	}
	if client := dialWebSocket(t, f, host("app-b"), tokenFor(aliceEmail)); !strings.Contains(client.status, " 403 ") {
		t.Fatalf("wrong app: %q", client.status)
	}
	if client := dialWebSocket(t, f, host("nope"), tokenFor(aliceEmail)); !strings.Contains(client.status, " 404 ") {
		t.Fatalf("unknown host: %q", client.status)
	}
}

func expectWebSocketClosed(t *testing.T, client *webSocketClient) {
	t.Helper()
	_ = client.conn.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, err := readFrame(client.reader); err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("the WebSocket stayed open after access ended")
			}
			return
		}
	}
}

func TestWebSocketClosesWhenAccessEnds(t *testing.T) {
	changes := map[string]func(f *fixture, port int){
		"guest removed":   func(f *fixture, port int) { f.publish("app-a", port) },
		"app unpublished": func(f *fixture, _ int) { f.unpublish("app-a") },
		"app moved":       func(f *fixture, port int) { f.publish("app-a", port+1, aliceEmail) },
		"team file gone":  func(f *fixture, _ int) { _ = os.Remove(f.config.TeamFile) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			port := f.upstream(webSocketEcho(t))
			f.publish("app-a", port, aliceEmail)
			client := dialWebSocket(t, f, host("app-a"), tokenFor(aliceEmail))
			if _, err := readFrame(client.reader); err != nil {
				t.Fatal(err)
			}
			change(f, port)
			expectWebSocketClosed(t, client)
		})
	}
}

func TestWebSocketStaysOpenWhileAccessLasts(t *testing.T) {
	f := newFixture(t)
	f.publish("app-a", f.upstream(webSocketEcho(t)), aliceEmail)
	client := dialWebSocket(t, f, host("app-a"), tokenFor(aliceEmail))
	if _, err := readFrame(client.reader); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2500 * time.Millisecond) // past two rechecks
	if err := writeFrame(client.conn, "still here", true); err != nil {
		t.Fatal(err)
	}
	if reply, err := readFrame(client.reader); err != nil || reply != "echo:still here" {
		t.Fatalf("%q %v", reply, err)
	}
}

func TestWebSocketClosesWhenTheTokenExpires(t *testing.T) {
	f := newFixture(t)
	f.publish("app-a", f.upstream(webSocketEcho(t)), aliceEmail)
	claims := goodClaims(aliceEmail)
	claims["exp"] = time.Now().Add(2 * time.Second).Unix()
	client := dialWebSocket(t, f, host("app-a"), sign(sharedKey, goodHeader(), claims))
	if _, err := readFrame(client.reader); err != nil {
		t.Fatal(err)
	}
	expectWebSocketClosed(t, client)
}

func TestEmailVectorsMatchTheOtherComponents(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "tests", "email_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Valid   map[string]string `json:"valid"`
		Invalid []string          `json:"invalid"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for raw, want := range vectors.Valid {
		if got, ok := normalizeEmail(raw); !ok || got != want {
			t.Errorf("%q: got %q %v", raw, got, ok)
		}
	}
	for _, raw := range vectors.Invalid {
		if got, ok := normalizeEmail(raw); ok {
			t.Errorf("%q accepted as %q", raw, got)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	good := func() *Config {
		return &Config{Listen: "127.0.0.1:8790", Domain: "example.net", TeamDomain: "t.cloudflareaccess.com", AUD: testAUD,
			TeamFile: "/t", RegistryDir: "/r", PortMin: 3000, PortMax: 3999, RecheckSeconds: 30}
	}
	if err := good().validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Config){
		"public listen":        func(c *Config) { c.Listen = "0.0.0.0:8790" },
		"name listen":          func(c *Config) { c.Listen = "localhost:8790" },
		"tailnet listen":       func(c *Config) { c.Listen = "100.64.0.1:8790" },
		"listen in app range":  func(c *Config) { c.Listen = "127.0.0.1:3500" },
		"placeholder domain":   func(c *Config) { c.Domain = "REPLACE_ME" },
		"placeholder team":     func(c *Config) { c.TeamDomain = "REPLACE_ME.cloudflareaccess.com" },
		"other issuer domain":  func(c *Config) { c.TeamDomain = "t.example.org" },
		"placeholder audience": func(c *Config) { c.AUD = "REPLACE_ME" },
		"no team file":         func(c *Config) { c.TeamFile = "" },
		"no recheck":           func(c *Config) { c.RecheckSeconds = 0 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			config := good()
			change(config)
			if config.validate() == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := loadConfig(filepath.Join("..", "deploy", "router.example.json")); err == nil {
		t.Fatal("the example config must be refused until its placeholders are replaced")
	}
	path := filepath.Join(t.TempDir(), "router.json")
	_ = os.WriteFile(path, []byte(`{"listen":"127.0.0.1:8790","domain":"example.net","team_domain":"t.cloudflareaccess.com","aud":"`+testAUD+`","team_file":"/t","registry_dir":"/r","skip_checks":true}`), 0o600)
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "skip_checks") {
		t.Fatalf("unknown key: %v", err)
	}
}

// The registry format is shared across languages, so read what the real gatekeeper code writes.
func TestReadsWhatTheGatekeeperWrites(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not available")
	}
	f := newFixture(t)
	port := f.nameApp("a")
	command := exec.Command(python, filepath.Join("..", "tests", "write_registry_entry.py"), f.config.RegistryDir,
		"app-a", strconv.Itoa(port), "Alice@Gmail.com")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, output)
	}
	f.expect(host("app-a"), tokenFor(aliceEmail), 200, "app:a")
	f.expect(host("app-a"), tokenFor(bobEmail), 403, "")
}
