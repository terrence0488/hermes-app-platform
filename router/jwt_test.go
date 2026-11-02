package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func readyVerifier(t *testing.T) (*Verifier, *certServer) {
	t.Helper()
	key, _ := keys()
	certs := newCertServer(t, jwk(testKid, &key.PublicKey))
	verifier := testVerifier(t, certs.URL)
	if err := verifier.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return verifier, certs
}

func TestValidToken(t *testing.T) {
	verifier, _ := readyVerifier(t)
	identity, err := verifier.Verify(context.Background(), tokenFor("Alice@GMail.com"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.Email != aliceEmail {
		t.Fatalf("email %q", identity.Email)
	}
}

func TestAudienceAsPlainString(t *testing.T) {
	verifier, _ := readyVerifier(t)
	key, _ := keys()
	claims := goodClaims(aliceEmail)
	claims["aud"] = testAUD
	if _, err := verifier.Verify(context.Background(), sign(key, goodHeader(), claims)); err != nil {
		t.Fatal(err)
	}
}

func TestRefusedTokens(t *testing.T) {
	verifier, _ := readyVerifier(t)
	key, other := keys()
	now := time.Now().Unix()
	claimsWith := func(name string, value any) map[string]any {
		claims := goodClaims(aliceEmail)
		claims[name] = value
		return claims
	}
	claimsWithout := func(name string) map[string]any {
		claims := goodClaims(aliceEmail)
		delete(claims, name)
		return claims
	}
	good := tokenFor(aliceEmail)
	parts := strings.Split(good, ".")
	forgedPayload := segment(claimsWith("email", ownerEmail))
	publicBytes := key.PublicKey.N.Bytes()
	mac := hmac.New(sha256.New, publicBytes)
	hsHeader := segment(map[string]any{"alg": "HS256", "kid": testKid})
	mac.Write([]byte(hsHeader + "." + parts[1]))
	hsToken := hsHeader + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	cases := map[string]string{
		"empty":                  "",
		"garbage":                "not-a-token",
		"two segments":           parts[0] + "." + parts[1],
		"four segments":          good + ".x",
		"oversize":               strings.Repeat("a", maxTokenBytes+1),
		"forged signature":       sign(other, goodHeader(), goodClaims(aliceEmail)),
		"tampered payload":       parts[0] + "." + forgedPayload + "." + parts[2],
		"empty signature":        parts[0] + "." + parts[1] + ".",
		"alg none":               segment(map[string]any{"alg": "none", "kid": testKid}) + "." + parts[1] + ".",
		"alg None":               segment(map[string]any{"alg": "None", "kid": testKid}) + "." + parts[1] + ".",
		"HS256 with public key":  hsToken,
		"RS512 header":           sign(key, map[string]any{"alg": "RS512", "kid": testKid}, goodClaims(aliceEmail)),
		"no kid":                 sign(key, map[string]any{"alg": "RS256"}, goodClaims(aliceEmail)),
		"crit header":            sign(key, map[string]any{"alg": "RS256", "kid": testKid, "crit": []string{"x"}}, goodClaims(aliceEmail)),
		"expired":                sign(key, goodHeader(), claimsWith("exp", now-1)),
		"no expiry":              sign(key, goodHeader(), claimsWithout("exp")),
		"not valid yet":          sign(key, goodHeader(), claimsWith("nbf", now+3600)),
		"issued in future":       sign(key, goodHeader(), claimsWith("iat", now+3600)),
		"wrong audience":         sign(key, goodHeader(), claimsWith("aud", []string{"f" + testAUD[1:]})),
		"audience missing":       sign(key, goodHeader(), claimsWithout("aud")),
		"audience empty":         sign(key, goodHeader(), claimsWith("aud", []string{})),
		"audience wrong type":    sign(key, goodHeader(), claimsWith("aud", 5)),
		"wrong issuer":           sign(key, goodHeader(), claimsWith("iss", "https://other-team.cloudflareaccess.com")),
		"issuer missing":         sign(key, goodHeader(), claimsWithout("iss")),
		"no email":               sign(key, goodHeader(), claimsWithout("email")),
		"email wrong type":       sign(key, goodHeader(), claimsWith("email", []string{aliceEmail})),
		"non-ASCII email":        sign(key, goodHeader(), claimsWith("email", "aliceK@gmail.com")),
		"email with space":       sign(key, goodHeader(), claimsWith("email", " alice@gmail.com")),
		"exp in wrong type":      sign(key, goodHeader(), claimsWith("exp", "soon")),
		"signature with padding": good + "=",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if identity, err := verifier.Verify(context.Background(), token); err == nil {
				t.Fatalf("accepted as %+v", identity)
			}
		})
	}
}

func TestUnknownKeyIDsCannotCauseAFetchStorm(t *testing.T) {
	verifier, certs := readyVerifier(t)
	key, _ := keys()
	verifier.mu.Lock()
	verifier.triedAt = time.Time{} // the last fetch was long ago
	verifier.mu.Unlock()
	before := certs.calls.Load()
	for i := 0; i < 20; i++ {
		token := sign(key, map[string]any{"alg": "RS256", "kid": "made-up"}, goodClaims(aliceEmail))
		if _, err := verifier.Verify(context.Background(), token); err == nil {
			t.Fatal("accepted an unknown key id")
		}
	}
	if got := certs.calls.Load() - before; got != 1 {
		t.Fatalf("%d fetches", got)
	}
}

func TestRotatedKeyIsPickedUpOnFirstUse(t *testing.T) {
	verifier, certs := readyVerifier(t)
	key, other := keys()
	certs.set(false, jwk(testKid, &key.PublicKey), jwk("key-2", &other.PublicKey))
	verifier.mu.Lock()
	verifier.triedAt = time.Time{}
	verifier.mu.Unlock()
	token := sign(other, map[string]any{"alg": "RS256", "kid": "key-2"}, goodClaims(aliceEmail))
	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
}

func TestNoKeysMeansRefusal(t *testing.T) {
	certs := newCertServer(t)
	certs.set(true)
	verifier := testVerifier(t, certs.URL)
	if _, err := verifier.Verify(context.Background(), tokenFor(aliceEmail)); err == nil {
		t.Fatal("accepted a token with no keys loaded")
	}
}

func TestFailedRefreshKeepsKeysUntilTooOld(t *testing.T) {
	verifier, certs := readyVerifier(t)
	certs.set(true)
	if err := verifier.Refresh(context.Background()); err == nil {
		t.Fatal("expected the refresh to fail")
	}
	if _, err := verifier.Verify(context.Background(), tokenFor(aliceEmail)); err != nil {
		t.Fatalf("old keys should still work: %v", err)
	}
	verifier.now = func() time.Time { return time.Now().Add(maxKeyAge + time.Minute) }
	token := sign(sharedKey, goodHeader(), func() map[string]any {
		claims := goodClaims(aliceEmail)
		claims["exp"] = time.Now().Add(maxKeyAge + time.Hour).Unix()
		return claims
	}())
	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("accepted a token against keys too old to trust")
	}
}

func TestParseKeysRefusesWeakAndForeignKeys(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	certs := newCertServer(t, jwk("weak", &weak.PublicKey), map[string]string{"kid": "ec", "kty": "EC"})
	verifier := testVerifier(t, certs.URL)
	if err := verifier.Refresh(context.Background()); err == nil {
		t.Fatal("accepted a certs document with no usable keys")
	}
}

func TestCertRedirectIsNotFollowed(t *testing.T) {
	key, _ := keys()
	certs := newCertServer(t, jwk(testKid, &key.PublicKey))
	redirect := newRedirectServer(t, certs.URL)
	verifier := testVerifier(t, redirect)
	if err := verifier.Refresh(context.Background()); err == nil {
		t.Fatal("followed a redirect")
	}
	if certs.calls.Load() != 0 {
		t.Fatal("reached the redirect target")
	}
}
