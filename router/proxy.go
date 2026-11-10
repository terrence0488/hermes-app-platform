package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"
)

const (
	tokenHeader     = "Cf-Access-Jwt-Assertion"
	headerUserEmail = "X-Hermes-App-User-Email"
	headerUserRole  = "X-Hermes-App-User-Role"
	headerAppName   = "X-Hermes-App-Name"
	roleTeam        = "team"
	roleGuest       = "guest"
)

// identityHeaders are common ways an app might learn who the user is. A client must not be able
// to set any of them, and only the router's own X-Hermes-App-* values reach the app.
var identityHeaders = map[string]bool{
	"forwarded": true, "remote-user": true, "x-real-ip": true, "x-remote-user": true,
	"x-remote-email": true, "x-user": true, "x-email": true, "x-auth-user": true,
	"x-auth-email": true, "x-auth-request-user": true, "x-auth-request-email": true,
	"x-auth-request-preferred-username": true, "x-forwarded-user": true, "x-forwarded-email": true,
	"x-forwarded-preferred-username": true, "x-forwarded-groups": true, "x-webauth-user": true,
	"x-webauth-email": true,
}

type target struct {
	app   string
	port  int
	email string
	role  string
}

type targetKey struct{}

// Router decides each request, then hands the allowed ones to the reverse proxy.
type Router struct {
	domainSuffix string
	verifier     *Verifier
	store        *Store
	recheck      time.Duration
	proxy        *httputil.ReverseProxy
	launcher     *Launcher // nil when no launcher is configured
}

func newRouter(config *Config, verifier *Verifier, store *Store) *Router {
	router := &Router{
		domainSuffix: "." + config.Domain,
		verifier:     verifier,
		store:        store,
		recheck:      config.recheckInterval(),
		launcher:     newLauncher(config, store),
	}
	router.proxy = &httputil.ReverseProxy{
		Rewrite:        rewrite,
		ModifyResponse: cleanResponse,
		FlushInterval:  -1, // pass streams on as they arrive
		ErrorHandler:   proxyError,
		ErrorLog:       log.Default(),
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			DisableCompression:  true,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     60 * time.Second,
		},
	}
	return router
}

// deny answers with a fixed body. Nothing from the request is repeated except a verified email.
func deny(w http.ResponseWriter, status int, body string) {
	header := w.Header()
	header.Set("Content-Type", "text/plain; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	fmt.Fprintln(w, body)
}

// appName returns the single label in front of the configured domain.
func (r *Router) appName(host string) (string, bool) {
	host = strings.ToLower(host)
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	name, found := strings.CutSuffix(host, r.domainSuffix)
	if !found || !validAppName(name) {
		return "", false
	}
	return name, true
}

// authorize answers with the target, or the status and body to refuse with.
func (r *Router) authorize(name, email string) (*target, int, string) {
	entry, err := r.store.App(name)
	if err != nil {
		log.Printf("cannot trust the registry: %v", err)
		return nil, http.StatusServiceUnavailable, "Service unavailable"
	}
	if entry == nil {
		return nil, http.StatusNotFound, "Not found"
	}
	team, _, err := r.store.Team()
	if err != nil {
		log.Printf("cannot trust the team file: %v", err)
		return nil, http.StatusServiceUnavailable, "Service unavailable"
	}
	if team[email] {
		return &target{app: name, port: entry.Port, email: email, role: roleTeam}, 0, ""
	}
	for _, guest := range entry.Guests {
		if guest == email {
			return &target{app: name, port: entry.Port, email: email, role: roleGuest}, 0, ""
		}
	}
	return nil, http.StatusForbidden, fmt.Sprintf("You are signed in as %s, which has no access to this app.", email)
}

func (r *Router) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodConnect || request.Method == http.MethodTrace {
		deny(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	// The token comes first, so nobody without one learns which apps exist.
	values := request.Header.Values(tokenHeader)
	if len(values) != 1 {
		log.Printf("refused host=%q: expected one token, got %d", request.Host, len(values))
		deny(w, http.StatusUnauthorized, "Sign-in required")
		return
	}
	identity, err := r.verifier.Verify(request.Context(), values[0])
	if err != nil {
		log.Printf("refused host=%q: %v", request.Host, err)
		deny(w, http.StatusUnauthorized, "Sign-in required")
		return
	}
	name, ok := r.appName(request.Host)
	if !ok {
		log.Printf("refused host=%q email=%q: not an app hostname", request.Host, identity.Email)
		deny(w, http.StatusNotFound, "Not found")
		return
	}
	if r.launcher != nil && name == r.launcher.host {
		r.launcher.ServeHTTP(w, request, identity.Email)
		return
	}
	allowed, status, body := r.authorize(name, identity.Email)
	if allowed == nil {
		log.Printf("refused app=%q email=%q status=%d", name, identity.Email, status)
		deny(w, status, body)
		return
	}
	log.Printf("allowed app=%q email=%q role=%s method=%s", name, identity.Email, allowed.role, request.Method)
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	go r.watch(ctx, cancel, name, allowed, identity.Expires)
	r.proxy.ServeHTTP(w, request.WithContext(context.WithValue(ctx, targetKey{}, allowed)))
}

// watch ends a long-lived connection (a WebSocket or a stream) once its access is gone: the guest
// was removed, the app was unpublished or moved, or the token expired.
func (r *Router) watch(ctx context.Context, cancel context.CancelFunc, name string, allowed *target, expires time.Time) {
	ticker := time.NewTicker(r.recheck)
	defer ticker.Stop()
	expiry := time.NewTimer(time.Until(expires))
	defer expiry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-expiry.C:
			log.Printf("closed app=%q email=%q: token expired", name, allowed.email)
			cancel()
			return
		case <-ticker.C:
			current, status, _ := r.authorize(name, allowed.email)
			if current == nil || current.port != allowed.port {
				log.Printf("closed app=%q email=%q: access ended (status %d)", name, allowed.email, status)
				cancel()
				return
			}
		}
	}
}

func rewrite(pr *httputil.ProxyRequest) {
	allowed := pr.In.Context().Value(targetKey{}).(*target)
	pr.Out.URL.Scheme = "http"
	pr.Out.URL.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(allowed.port))
	pr.Out.Host = pr.In.Host
	header := pr.Out.Header
	cleanRequestHeaders(header)
	header.Set(headerUserEmail, allowed.email)
	header.Set(headerUserRole, allowed.role)
	header.Set(headerAppName, allowed.app)
	header.Set("X-Forwarded-Host", pr.In.Host)
	header.Set("X-Forwarded-Proto", "https")
	if client := pr.In.Header.Get("Cf-Connecting-Ip"); client != "" {
		header.Set("X-Forwarded-For", client)
	}
}

// cleanRequestHeaders treats _ like -, because many app frameworks read both as the same header.
func cleanRequestHeaders(header http.Header) {
	for key := range header {
		normal := strings.ReplaceAll(strings.ToLower(key), "_", "-")
		if identityHeaders[normal] || strings.HasPrefix(normal, "x-hermes-app-") || strings.HasPrefix(normal, "cf-access-") {
			delete(header, key)
		}
	}
	stripAccessCookies(header)
}

// isAccessCookie covers CF_Authorization and its siblings. An app holding a user's token could
// replay it to reach everything else that user can reach.
func isAccessCookie(name string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(name)), "cf_")
}

func stripAccessCookies(header http.Header) {
	lines := header.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	var kept []string
	for _, line := range lines {
		for _, pair := range strings.Split(line, ";") {
			name, _, _ := strings.Cut(pair, "=")
			if strings.TrimSpace(pair) != "" && !isAccessCookie(name) {
				kept = append(kept, strings.TrimSpace(pair))
			}
		}
	}
	header.Del("Cookie")
	if len(kept) > 0 {
		header.Set("Cookie", strings.Join(kept, "; "))
	}
}

// cleanResponse stops one app reaching beyond its own hostname through cookies: it cannot set or
// clear the Access cookies, and every cookie it sets stays host-only.
func cleanResponse(response *http.Response) error {
	cookies := response.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return nil
	}
	response.Header.Del("Set-Cookie")
	for _, cookie := range cookies {
		parts := strings.Split(cookie, ";")
		name, _, _ := strings.Cut(parts[0], "=")
		if isAccessCookie(name) {
			continue
		}
		kept := parts[:1]
		for _, attribute := range parts[1:] {
			key, _, _ := strings.Cut(attribute, "=")
			if !strings.EqualFold(strings.TrimSpace(key), "domain") {
				kept = append(kept, attribute)
			}
		}
		response.Header.Add("Set-Cookie", strings.Join(kept, ";"))
	}
	return nil
}

func proxyError(w http.ResponseWriter, request *http.Request, err error) {
	allowed := request.Context().Value(targetKey{}).(*target)
	log.Printf("upstream failed app=%q port=%d: %v", allowed.app, allowed.port, err)
	deny(w, http.StatusBadGateway, "The app is not responding.")
}
