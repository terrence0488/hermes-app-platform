package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testDomain = "example.net"
	testTeam   = "test-team.cloudflareaccess.com"
	testAUD    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testKid    = "key-1"
	ownerEmail = "owner@gmail.com"
	aliceEmail = "alice@gmail.com"
	bobEmail   = "bob@gmail.com"
)

var (
	sharedKey     *rsa.PrivateKey
	sharedKeyOnce sync.Once
	otherKey      *rsa.PrivateKey
)

func init() {
	log.SetOutput(io.Discard)
}

func keys() (*rsa.PrivateKey, *rsa.PrivateKey) {
	sharedKeyOnce.Do(func() {
		var err error
		if sharedKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if otherKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return sharedKey, otherKey
}

func jwk(kid string, key *rsa.PublicKey) map[string]string {
	e := big.NewInt(int64(key.E)).Bytes()
	return map[string]string{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}
}

// certServer plays Cloudflare's certs endpoint, with a counter and a failure switch.
type certServer struct {
	*httptest.Server
	mu    sync.Mutex
	keys  []map[string]string
	fail  bool
	calls atomic.Int32
}

func newCertServer(t *testing.T, keys ...map[string]string) *certServer {
	t.Helper()
	server := &certServer{keys: keys}
	server.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		server.calls.Add(1)
		server.mu.Lock()
		defer server.mu.Unlock()
		if server.fail {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": server.keys})
	}))
	t.Cleanup(server.Close)
	return server
}

func (c *certServer) set(fail bool, keys ...map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fail = fail
	if keys != nil {
		c.keys = keys
	}
}

func segment(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func sign(key *rsa.PrivateKey, header, claims map[string]any) string {
	signing := segment(header) + "." + segment(claims)
	digest := sha256.Sum256([]byte(signing))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func goodClaims(email string) map[string]any {
	now := time.Now().Unix()
	return map[string]any{"iss": "https://" + testTeam, "aud": []string{testAUD}, "email": email,
		"iat": now - 10, "nbf": now - 10, "exp": now + 3600, "type": "app", "sub": "user-id"}
}

func goodHeader() map[string]any {
	return map[string]any{"alg": "RS256", "kid": testKid}
}

func tokenFor(email string) string {
	key, _ := keys()
	return sign(key, goodHeader(), goodClaims(email))
}

func testConfig(dir string) *Config {
	return &Config{Listen: "127.0.0.1:8790", Domain: testDomain, TeamDomain: testTeam, AUD: testAUD,
		TeamFile: filepath.Join(dir, "team.txt"), RegistryDir: filepath.Join(dir, "registry"),
		PortMin: 1024, PortMax: 65535, RecheckSeconds: 1}
}

func testVerifier(t *testing.T, certsURL string) *Verifier {
	t.Helper()
	verifier := newVerifier(testConfig(t.TempDir()))
	verifier.certsURL = certsURL
	return verifier
}

// fixture is a whole router on a real loopback socket, in front of real upstream servers.
type fixture struct {
	t        *testing.T
	dir      string
	config   *Config
	verifier *Verifier
	store    *Store
	server   *httptest.Server
	certs    *certServer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, _ := keys()
	dir := t.TempDir()
	config := testConfig(dir)
	certs := newCertServer(t, jwk(testKid, &key.PublicKey))
	verifier := newVerifier(config)
	verifier.certsURL = certs.URL
	if err := verifier.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	store := newStore(config)
	store.trustedUID = os.Getuid()
	if err := os.Mkdir(config.RegistryDir, 0o750); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, dir: dir, config: config, verifier: verifier, store: store, certs: certs}
	f.writeTeam(ownerEmail + "\n")
	f.server = httptest.NewServer(newRouter(config, verifier, store))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fixture) writeFile(path, text string, mode os.FileMode) {
	f.t.Helper()
	temp := path + ".tmp"
	if err := os.WriteFile(temp, []byte(text), mode); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(temp, mode); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Rename(temp, path); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) writeTeam(text string) {
	f.writeFile(f.config.TeamFile, text, 0o640)
}

func (f *fixture) publish(name string, port int, guests ...string) {
	f.t.Helper()
	if guests == nil {
		guests = []string{}
	}
	data, _ := json.Marshal(Entry{Name: name, Port: port, CreatedBy: "telegram:1", CreatedAt: "now", Guests: guests})
	f.writeFile(filepath.Join(f.config.RegistryDir, name+".json"), string(data), 0o640)
}

func (f *fixture) unpublish(name string) {
	f.t.Helper()
	if err := os.Remove(filepath.Join(f.config.RegistryDir, name+".json")); err != nil {
		f.t.Fatal(err)
	}
}

// upstream starts a real app and returns its port.
func (f *fixture) upstream(handler http.Handler) int {
	f.t.Helper()
	server := httptest.NewServer(handler)
	f.t.Cleanup(server.CloseClientConnections)
	f.t.Cleanup(server.Close)
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	number, _ := strconv.Atoi(port)
	return number
}

// nameApp returns a port whose app answers with its own name.
func (f *fixture) nameApp(name string) int {
	return f.upstream(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "app:"+name)
	}))
}

// get sends a request with the token and Host given, and returns the status and body.
func (f *fixture) get(host, token string, headers map[string]string) (int, string) {
	f.t.Helper()
	request, err := http.NewRequest(http.MethodGet, f.server.URL+"/", nil)
	if err != nil {
		f.t.Fatal(err)
	}
	request.Host = host
	if token != "" {
		request.Header.Set(tokenHeader, token)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, strings.TrimSpace(string(body))
}

func (f *fixture) expect(host, token string, status int, bodyContains string) {
	f.t.Helper()
	gotStatus, gotBody := f.get(host, token, nil)
	if gotStatus != status || !strings.Contains(gotBody, bodyContains) {
		f.t.Fatalf("host %s: got %d %q, want %d containing %q", host, gotStatus, gotBody, status, bodyContains)
	}
}
