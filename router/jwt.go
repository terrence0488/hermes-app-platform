package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	maxTokenBytes    = 16 << 10
	maxCertsBytes    = 1 << 20
	minRSABits       = 2048
	clockLeeway      = 30 * time.Second
	refreshInterval  = time.Hour
	retryInterval    = time.Minute
	unknownKidWait   = time.Minute // a stranger's made-up key id can cost at most this many fetches
	maxKeyAge        = 24 * time.Hour
	certFetchTimeout = 10 * time.Second
)

// Identity is what a verified Cloudflare Access token says about the caller.
type Identity struct {
	Email   string
	Expires time.Time
}

// Verifier checks Cloudflare Access tokens against the team's published keys. Only RS256 is
// accepted, so a token cannot choose how it is checked.
type Verifier struct {
	issuer   string
	audience string
	certsURL string
	client   *http.Client
	now      func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	triedAt   time.Time
}

func newVerifier(config *Config) *Verifier {
	return &Verifier{
		issuer:   config.issuer(),
		audience: config.AUD,
		certsURL: config.certsURL(),
		now:      time.Now,
		client: &http.Client{
			Timeout: certFetchTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirects are not followed")
			},
			Transport: &http.Transport{Proxy: nil},
		},
	}
}

// Refresh fetches the team's keys. A failure keeps the old keys, which stop counting at maxKeyAge.
func (v *Verifier) Refresh(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.certsURL, nil)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.triedAt = v.now()
	v.mu.Unlock()
	response, err := v.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("certs endpoint returned %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCertsBytes))
	if err != nil {
		return err
	}
	keys, err := parseKeys(body)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.keys, v.fetchedAt = keys, v.now()
	v.mu.Unlock()
	return nil
}

// RunRefresh keeps the keys current until the context ends.
func (v *Verifier) RunRefresh(ctx context.Context) {
	for {
		wait := refreshInterval
		if err := v.Refresh(ctx); err != nil {
			log.Printf("could not refresh Access keys: %v", err)
			wait = retryInterval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func parseKeys(body []byte) (map[string]*rsa.PublicKey, error) {
	var document struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("certs are not valid JSON: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range document.Keys {
		if jwk.Kty != "RSA" || jwk.Kid == "" {
			continue
		}
		modulus, err := base64.RawURLEncoding.Strict().DecodeString(jwk.N)
		if err != nil {
			continue
		}
		exponent, err := base64.RawURLEncoding.Strict().DecodeString(jwk.E)
		if err != nil || len(exponent) == 0 || len(exponent) > 4 {
			continue
		}
		n := new(big.Int).SetBytes(modulus)
		e := new(big.Int).SetBytes(exponent).Int64()
		if n.BitLen() < minRSABits || e < 3 || e%2 == 0 {
			continue
		}
		keys[jwk.Kid] = &rsa.PublicKey{N: n, E: int(e)}
	}
	if len(keys) == 0 {
		return nil, errors.New("certs contain no usable RSA keys")
	}
	return keys, nil
}

func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	key, fresh := v.keys[kid], !v.fetchedAt.IsZero() && v.now().Sub(v.fetchedAt) <= maxKeyAge
	mayFetch := key == nil && v.now().Sub(v.triedAt) >= unknownKidWait
	v.mu.Unlock()
	if key != nil && fresh {
		return key, nil
	}
	if key != nil {
		return nil, errors.New("the Access keys are too old to trust")
	}
	if !mayFetch {
		return nil, errors.New("unknown key id")
	}
	// A new key id can be a real rotation.
	if err := v.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("unknown key id, and refresh failed: %w", err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if key := v.keys[kid]; key != nil {
		return key, nil
	}
	return nil, errors.New("unknown key id")
}

type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func decodeSegment(segment string) ([]byte, error) {
	return base64.RawURLEncoding.Strict().DecodeString(segment)
}

// Verify checks signature, issuer, audience and times, and returns the caller's normalised email.
// The error text is for the log only.
func (v *Verifier) Verify(ctx context.Context, token string) (*Identity, error) {
	if token == "" {
		return nil, errors.New("no token")
	}
	if len(token) > maxTokenBytes {
		return nil, errors.New("token too long")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("token is not three segments")
	}
	rawHeader, err := decodeSegment(parts[0])
	if err != nil {
		return nil, errors.New("bad token header encoding")
	}
	var header struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Crit json.RawMessage `json:"crit"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return nil, errors.New("bad token header")
	}
	if header.Alg != "RS256" {
		return nil, errors.New("token algorithm is not RS256")
	}
	if header.Kid == "" || len(header.Crit) != 0 {
		return nil, errors.New("token header has no key id, or has critical extensions")
	}
	signature, err := decodeSegment(parts[2])
	if err != nil {
		return nil, errors.New("bad token signature encoding")
	}
	key, err := v.key(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("bad token signature")
	}
	// Nothing in the payload is looked at until the signature has been checked.
	rawClaims, err := decodeSegment(parts[1])
	if err != nil {
		return nil, errors.New("bad token payload encoding")
	}
	var claims struct {
		Iss   string   `json:"iss"`
		Aud   audience `json:"aud"`
		Exp   *float64 `json:"exp"`
		Nbf   *float64 `json:"nbf"`
		Iat   *float64 `json:"iat"`
		Email string   `json:"email"`
	}
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return nil, errors.New("bad token payload")
	}
	if claims.Iss != v.issuer {
		return nil, errors.New("wrong issuer")
	}
	matched := false
	for _, value := range claims.Aud {
		matched = matched || value == v.audience
	}
	if !matched {
		return nil, errors.New("wrong audience")
	}
	now := v.now()
	if claims.Exp == nil {
		return nil, errors.New("token has no expiry")
	}
	expires := time.Unix(int64(*claims.Exp), 0)
	if !now.Before(expires) {
		return nil, errors.New("token expired")
	}
	if claims.Nbf != nil && now.Add(clockLeeway).Before(time.Unix(int64(*claims.Nbf), 0)) {
		return nil, errors.New("token not valid yet")
	}
	if claims.Iat != nil && now.Add(clockLeeway).Before(time.Unix(int64(*claims.Iat), 0)) {
		return nil, errors.New("token issued in the future")
	}
	// A service token has no email, and only a person can be on the team or a guest list.
	email, ok := normalizeEmail(claims.Email)
	if !ok {
		return nil, errors.New("token has no usable email")
	}
	return &Identity{Email: email, Expires: expires}, nil
}
