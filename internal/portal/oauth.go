package portal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Profile struct{ Subject, Email, Name string }

type Provider struct {
	Name         string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
	FetchProfile func(ctx context.Context, hc *http.Client, p Provider, accessToken string) (Profile, error)
	EmailsURL    string
}

func getJSON(ctx context.Context, hc *http.Client, u, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s returned %d", u, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

func Google(clientID, secret string) Provider {
	return Provider{
		Name:         "google",
		ClientID:     clientID,
		ClientSecret: secret,
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		UserInfoURL:  "https://openidconnect.googleapis.com/v1/userinfo",
		Scopes:       []string{"openid", "email", "profile"},
		FetchProfile: func(ctx context.Context, hc *http.Client, p Provider, tok string) (Profile, error) {
			var u struct {
				Sub           string `json:"sub"`
				Email         string `json:"email"`
				EmailVerified bool   `json:"email_verified"`
				Name          string `json:"name"`
			}
			if err := getJSON(ctx, hc, p.UserInfoURL, tok, &u); err != nil {
				return Profile{}, err
			}
			if u.Sub == "" || u.Email == "" || !u.EmailVerified {
				return Profile{}, errors.New("google account has no verified email")
			}
			return Profile{Subject: u.Sub, Email: strings.ToLower(u.Email), Name: u.Name}, nil
		},
	}
}

var GitHub = Github

func Github(clientID, secret string) Provider {
	return Provider{
		Name:         "github",
		ClientID:     clientID,
		ClientSecret: secret,
		AuthURL:      "https://github.com/login/oauth/authorize",
		TokenURL:     "https://github.com/login/oauth/access_token",
		UserInfoURL:  "https://api.github.com/user",
		EmailsURL:    "https://api.github.com/user/emails",
		Scopes:       []string{"read:user", "user:email"},
		FetchProfile: func(ctx context.Context, hc *http.Client, p Provider, tok string) (Profile, error) {
			var u struct {
				ID    int64  `json:"id"`
				Login string `json:"login"`
				Name  string `json:"name"`
			}
			if err := getJSON(ctx, hc, p.UserInfoURL, tok, &u); err != nil {
				return Profile{}, err
			}
			var emails []struct {
				Email    string `json:"email"`
				Primary  bool   `json:"primary"`
				Verified bool   `json:"verified"`
			}
			if err := getJSON(ctx, hc, p.EmailsURL, tok, &emails); err != nil {
				return Profile{}, err
			}
			email := ""
			for _, e := range emails {
				if e.Primary && e.Verified {
					email = e.Email
				}
			}
			if u.ID == 0 || email == "" {
				return Profile{}, errors.New("github account has no verified primary email")
			}
			name := u.Name
			if name == "" {
				name = u.Login
			}
			return Profile{Subject: fmt.Sprint(u.ID), Email: strings.ToLower(email), Name: name}, nil
		},
	}
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

type oauthState struct {
	State    string    `json:"s"`
	Verifier string    `json:"v"`
	Provider string    `json:"p"`
	Exp      time.Time `json:"e"`
}

func seal(secret []byte, v oauthState) string {
	b, _ := json.Marshal(v)
	body := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func unseal(secret []byte, s string, now time.Time) (oauthState, error) {
	body, sig, ok := strings.Cut(s, ".")
	if !ok {
		return oauthState{}, errors.New("malformed state")
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(body))
	want := base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return oauthState{}, errors.New("bad state signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return oauthState{}, err
	}
	var v oauthState
	if err := json.Unmarshal(raw, &v); err != nil {
		return oauthState{}, err
	}
	if now.After(v.Exp) {
		return oauthState{}, errors.New("state expired")
	}
	return v, nil
}

func (p Provider) authorizeURL(redirect, state, challenge string) string {
	q := url.Values{
		"response_type": {"code"}, "client_id": {p.ClientID}, "redirect_uri": {redirect},
		"scope": {strings.Join(p.Scopes, " ")}, "state": {state},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	return p.AuthURL + "?" + q.Encode()
}

func (p Provider) exchange(ctx context.Context, hc *http.Client, code, verifier, redirect string) (string, error) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {p.ClientID}, "client_secret": {p.ClientSecret}, "code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	if resp.StatusCode != 200 || tok.AccessToken == "" {
		return "", fmt.Errorf("token exchange failed (%d %s)", resp.StatusCode, tok.Error)
	}
	return tok.AccessToken, nil
}
