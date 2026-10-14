package portal

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"arcpay/internal/core"
	"arcpay/internal/eth"
	"arcpay/internal/signer"
	"arcpay/internal/store"
)

type Registrar interface {
	RegisterDestination(ctx context.Context, merchantID, address, requestedBy string) (signer.Destination, error)
	Destination(ctx context.Context, merchantID string) (signer.Destination, error)
}

type Server struct {
	Store             store.Store
	Registrar         Registrar
	Providers         map[string]Provider
	BaseURL           string
	StateSecret       []byte
	PostLoginURL      string
	SessionTTL        time.Duration
	CookieInsecure    bool
	AllowedOrigins    []string
	AllowHTTPWebhooks bool
	HTTP              *http.Client
	Now               func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) hc() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (s *Server) ttl() time.Duration {
	if s.SessionTTL > 0 {
		return s.SessionTTL
	}
	return 14 * 24 * time.Hour
}

const (
	sessionCookie       = "railpay_session"
	legacySessionCookie = "arcpay_session"
	stateCookie         = "railpay_oauth"
)

func (s *Server) getSessionCookie(r *http.Request) (*http.Cookie, error) {
	c, err := r.Cookie(sessionCookie)
	if err == nil && c.Value != "" {
		return c, nil
	}
	return r.Cookie(legacySessionCookie)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /login", s.loginPage)

	// Traditional email & password authentication
	mux.HandleFunc("POST /auth/signup", s.signup)
	mux.HandleFunc("POST /auth/register", s.signup)
	mux.HandleFunc("POST /api/auth/signup", s.signup)
	mux.HandleFunc("POST /api/auth/register", s.signup)

	mux.HandleFunc("POST /auth/login", s.login)
	mux.HandleFunc("POST /auth/signin", s.login)
	mux.HandleFunc("POST /api/auth/login", s.login)
	mux.HandleFunc("POST /api/auth/signin", s.login)

	mux.HandleFunc("POST /auth/logout", s.logout)
	mux.HandleFunc("POST /api/auth/logout", s.logout)

	if s.AllowHTTPWebhooks {
		mux.HandleFunc("POST /auth/dev/login", s.devLogin)
	}
	mux.HandleFunc("GET /auth/{provider}/start", s.start)
	mux.HandleFunc("GET /auth/{provider}/callback", s.callback)

	mux.HandleFunc("GET /api/me", s.authed(s.me))
	mux.HandleFunc("PATCH /api/merchant", s.authed(s.patchMerchant))
	mux.HandleFunc("POST /api/merchant/webhook_secret/rotate", s.authed(s.rotateSecret))
	mux.HandleFunc("GET /api/settlement", s.authed(s.getSettlement))
	mux.HandleFunc("PUT /api/settlement", s.authed(s.putSettlement))
	mux.HandleFunc("GET /api/keys", s.authed(s.listKeys))
	mux.HandleFunc("POST /api/keys", s.authed(s.createKey))
	mux.HandleFunc("DELETE /api/keys/{id}", s.authed(s.revokeKey))
	mux.HandleFunc("GET /api/intents", s.authed(s.listIntents))
	mux.HandleFunc("GET /api/intents/{id}", s.authed(s.getIntent))
	mux.HandleFunc("GET /api/payouts", s.authed(s.listPayouts))
	mux.HandleFunc("GET /api/stats", s.authed(s.stats))
	mux.HandleFunc("GET /api/webhooks/deliveries", s.authed(s.deliveries))
	return s.cors(mux)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"message": msg}})
}

func (s *Server) originAllowed(o string) bool {
	if o == "" {
		return false
	}
	if u, err := url.Parse(s.BaseURL); err == nil && o == u.Scheme+"://"+u.Host {
		return true
	}
	for _, a := range s.AllowedOrigins {
		if o == a {
			return true
		}
	}
	if s.AllowHTTPWebhooks && (strings.HasPrefix(o, "http://localhost:") || strings.HasPrefix(o, "http://127.0.0.1:")) {
		return true
	}
	return false
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			if s.originAllowed(o) {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", o)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, Authorization, Idempotency-Key")
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				h.Add("Vary", "Origin")
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	return s.originAllowed(o)
}

type session struct {
	core.Session
	user     core.User
	merchant core.Merchant
}

type authedHandler func(w http.ResponseWriter, r *http.Request, ses session)

func (s *Server) authed(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := s.getSessionCookie(r)
		if err != nil || c.Value == "" {
			writeErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		ss, err := s.Store.SessionByToken(r.Context(), c.Value, s.now())
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "session expired")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.originOK(r) {
				writeErr(w, http.StatusForbidden, "cross-origin request refused")
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(ss.CSRF)) != 1 {
				writeErr(w, http.StatusForbidden, "missing or invalid CSRF token")
				return
			}
		}
		u, err := s.Store.UserByID(r.Context(), ss.UserID)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "account not found")
			return
		}
		m, err := s.Store.MerchantByID(r.Context(), ss.MerchantID)
		if err != nil || m.Status != "active" {
			writeErr(w, http.StatusForbidden, "merchant account is not active")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		h(w, r, session{Session: ss, user: u, merchant: m})
	}
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}




func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "RailPay API",
		"version": "v1",
		"status":  "online",
		"network": "arc",
	})
}

func (s *Server) devLogin(w http.ResponseWriter, r *http.Request) {
	if !s.AllowHTTPWebhooks {
		http.NotFound(w, r)
		return
	}
	u, m, _, err := s.Store.LoginUser(r.Context(), store.LoginProfile{
		Provider: "dev", Subject: "dev_merchant", Email: "dev@railpay.xyz", Name: "Dev Merchant",
	}, s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	token, _, err := s.Store.CreateSession(r.Context(), u.ID, m.ID, s.ttl(), s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.setCookie(w, sessionCookie, token, "/", int(s.ttl().Seconds()))
	dest := s.PostLoginURL
	if dest == "" {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func (s *Server) providerNames() []string {
	var n []string
	for k := range s.Providers {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

func (s *Server) loginPage(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"providers": s.providerNames(),
		"dev_mode":  s.AllowHTTPWebhooks,
	})
}

func (s *Server) redirectURI(provider string) string {
	return strings.TrimRight(s.BaseURL, "/") + "/auth/" + provider + "/callback"
}

func (s *Server) setCookie(w http.ResponseWriter, name, value, path string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, MaxAge: maxAge,
		HttpOnly: true, Secure: !s.CookieInsecure, SameSite: http.SameSiteLaxMode})
}

func (s *Server) start(w http.ResponseWriter, r *http.Request) {
	p, ok := s.Providers[r.PathValue("provider")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	st := oauthState{State: randToken(24), Verifier: randToken(48), Provider: p.Name, Exp: s.now().Add(10 * time.Minute)}
	s.setCookie(w, stateCookie, seal(s.StateSecret, st), "/auth", 600)
	http.Redirect(w, r, p.authorizeURL(s.redirectURI(p.Name), st.State, pkceChallenge(st.Verifier)), http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	p, ok := s.Providers[r.PathValue("provider")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	fail := func(code int, msg string) {
		s.setCookie(w, stateCookie, "", "/auth", -1)
		writeErr(w, code, msg)
	}
	c, err := r.Cookie(stateCookie)
	if err != nil {
		fail(http.StatusBadRequest, "login session missing; start again")
		return
	}
	st, err := unseal(s.StateSecret, c.Value, s.now())
	if err != nil || st.Provider != p.Name || subtle.ConstantTimeCompare([]byte(st.State), []byte(r.URL.Query().Get("state"))) != 1 {
		fail(http.StatusBadRequest, "invalid or expired login state; start again")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		fail(http.StatusBadRequest, "the provider denied the login: "+e)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		fail(http.StatusBadRequest, "missing authorization code")
		return
	}
	tok, err := p.exchange(r.Context(), s.hc(), code, st.Verifier, s.redirectURI(p.Name))
	if err != nil {
		fail(http.StatusBadGateway, "could not complete login with the provider")
		return
	}
	prof, err := p.FetchProfile(r.Context(), s.hc(), p, tok)
	if err != nil {
		fail(http.StatusForbidden, err.Error())
		return
	}
	u, m, _, err := s.Store.LoginUser(r.Context(), store.LoginProfile{Provider: p.Name, Subject: prof.Subject, Email: prof.Email, Name: prof.Name}, s.now())
	if err != nil {
		fail(http.StatusInternalServerError, "could not sign you in")
		return
	}
	if m.Status != "active" {
		fail(http.StatusForbidden, "this merchant account is suspended")
		return
	}
	token, _, err := s.Store.CreateSession(r.Context(), u.ID, m.ID, s.ttl(), s.now())
	if err != nil {
		fail(http.StatusInternalServerError, "could not create a session")
		return
	}
	s.setCookie(w, stateCookie, "", "/auth", -1)
	s.setCookie(w, sessionCookie, token, "/", int(s.ttl().Seconds()))
	dest := s.PostLoginURL
	if dest == "" {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

type signupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	if !s.originOK(r) {
		writeErr(w, http.StatusForbidden, "cross-origin request refused")
		return
	}
	var req signupRequest
	if !decodeBody(w, r, &req) {
		return
	}

	cleanEmail, err := core.ValidEmail(req.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "a valid email address is required")
		return
	}
	req.Email = cleanEmail

	if len(req.Password) < 8 {
		writeErr(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if len(req.Password) > 72 {
		writeErr(w, http.StatusBadRequest, "password is too long (maximum 72 characters)")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to secure password")
		return
	}

	u, m, err := s.Store.SignUpPassword(r.Context(), req.Email, string(hash), req.Name, s.now())
	if err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			writeErr(w, http.StatusConflict, "an account with this email already exists")
			return
		}
		if errors.Is(err, store.ErrInvalid) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, "failed to create account")
		return
	}

	token, sess, err := s.Store.CreateSession(r.Context(), u.ID, m.ID, s.ttl(), s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	s.setCookie(w, sessionCookie, token, "/", int(s.ttl().Seconds()))

	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":         true,
		"token":      token,
		"csrf_token": sess.CSRF,
		"user": map[string]string{
			"id":       u.ID,
			"email":    u.Email,
			"name":     u.Name,
			"provider": u.Provider,
		},
		"merchant": viewMerchant(m),
	})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.originOK(r) {
		writeErr(w, http.StatusForbidden, "cross-origin request refused")
		return
	}
	var req loginRequest
	if !decodeBody(w, r, &req) {
		return
	}

	cleanEmail, err := core.ValidEmail(req.Email)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	req.Email = cleanEmail

	if req.Password == "" {
		writeErr(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	u, m, hash, err := s.Store.AuthenticatePassword(r.Context(), req.Email)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	if m.Status != "active" {
		writeErr(w, http.StatusForbidden, "account suspended")
		return
	}

	token, sess, err := s.Store.CreateSession(r.Context(), u.ID, m.ID, s.ttl(), s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	s.setCookie(w, sessionCookie, token, "/", int(s.ttl().Seconds()))

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"token":      token,
		"csrf_token": sess.CSRF,
		"user": map[string]string{
			"id":       u.ID,
			"email":    u.Email,
			"name":     u.Name,
			"provider": u.Provider,
		},
		"merchant": viewMerchant(m),
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := s.getSessionCookie(r); err == nil && c.Value != "" {
		_ = s.Store.DeleteSession(r.Context(), c.Value)
	}
	s.setCookie(w, sessionCookie, "", "/", -1)
	s.setCookie(w, legacySessionCookie, "", "/", -1)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return "••••"
	}
	return "••••" + s[len(s)-4:]
}

type merchantView struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Email             string    `json:"email"`
	FeeBps            uint32    `json:"fee_bps"`
	WebhookURL        string    `json:"webhook_url"`
	WebhookSecret     string    `json:"webhook_secret"`
	SettlementAddress string    `json:"settlement_address"`
	CreatedAt         time.Time `json:"created_at"`
}

func viewMerchant(m core.Merchant) merchantView {
	return merchantView{ID: m.ID, Name: m.Name, Email: m.Email, FeeBps: m.FeeBps, WebhookURL: m.WebhookURL,
		WebhookSecret: maskSecret(m.WebhookSecret), SettlementAddress: m.SettlementAddress, CreatedAt: m.CreatedAt}
}

func (s *Server) me(w http.ResponseWriter, _ *http.Request, ses session) {
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       map[string]string{"id": ses.user.ID, "email": ses.user.Email, "name": ses.user.Name, "provider": ses.user.Provider},
		"merchant":   viewMerchant(ses.merchant),
		"csrf_token": ses.CSRF,
	})
}

func (s *Server) validWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("webhook_url must be a valid URL without credentials")
	}
	if u.Scheme != "https" && !(s.AllowHTTPWebhooks && u.Scheme == "http") {
		return errors.New("webhook_url must use https")
	}
	if len(raw) > 500 {
		return errors.New("webhook_url is too long")
	}
	return nil
}

func (s *Server) patchMerchant(w http.ResponseWriter, r *http.Request, ses session) {
	var req struct {
		Name        *string `json:"name"`
		WebhookURL  *string `json:"webhook_url"`
		EmailOptOut *bool   `json:"email_opt_out"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Name != nil {
		n := strings.TrimSpace(*req.Name)
		if n == "" || len(n) > 80 {
			writeErr(w, http.StatusBadRequest, "name must be 1-80 characters")
			return
		}
		req.Name = &n
	}
	if req.WebhookURL != nil && *req.WebhookURL != "" {
		if err := s.validWebhookURL(*req.WebhookURL); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	m, err := s.Store.UpdateMerchant(r.Context(), ses.merchant.ID, func(m *core.Merchant) error {
		if req.Name != nil {
			m.Name = *req.Name
		}
		if req.WebhookURL != nil {
			m.WebhookURL = *req.WebhookURL
			if m.WebhookURL != "" && m.WebhookSecret == "" {
				m.WebhookSecret = "whsec_" + randToken(24)
			}
		}
		if req.EmailOptOut != nil {
			m.EmailOptOut = *req.EmailOptOut
		}
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not update the merchant")
		return
	}
	writeJSON(w, http.StatusOK, viewMerchant(m))
}

func (s *Server) rotateSecret(w http.ResponseWriter, r *http.Request, ses session) {
	secret := "whsec_" + randToken(24)
	if _, err := s.Store.UpdateMerchant(r.Context(), ses.merchant.ID, func(m *core.Merchant) error {
		m.WebhookSecret = secret
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not rotate the secret")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"webhook_secret": secret})
}

func (s *Server) settlementView(r *http.Request, m core.Merchant) map[string]any {
	out := map[string]any{"requested_address": m.SettlementAddress, "requested_at": nilTime(m.SettlementRequestedAt)}
	if d, err := s.Registrar.Destination(r.Context(), m.ID); err == nil {
		out["active_address"], out["active_since"] = d.Active, nilTime(d.ActiveSince)
		out["pending_address"], out["pending_activates_at"] = d.Pending, nilTime(d.ActivatesAt)
		out["pending_needs_approval"] = d.NeedsApproval
	} else {
		out["signer_error"] = "settlement status is temporarily unavailable"
	}
	return out
}

func nilTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (s *Server) getSettlement(w http.ResponseWriter, r *http.Request, ses session) {
	writeJSON(w, http.StatusOK, s.settlementView(r, ses.merchant))
}

func (s *Server) putSettlement(w http.ResponseWriter, r *http.Request, ses session) {
	var req struct {
		Address string `json:"address"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	a, err := eth.ParseAddress(strings.TrimSpace(req.Address))
	if err != nil || a.IsZero() {
		writeErr(w, http.StatusBadRequest, "address must be a valid 0x wallet address (mixed-case addresses must have a valid checksum)")
		return
	}
	if _, err := s.Registrar.RegisterDestination(r.Context(), ses.merchant.ID, a.Lower(), ses.user.Email); err != nil {
		var pe *signer.PolicyError
		if errors.As(err, &pe) {
			writeErr(w, http.StatusUnprocessableEntity, pe.Reason)
			return
		}
		writeErr(w, http.StatusBadGateway, "could not register the address right now; try again shortly")
		return
	}
	m, err := s.Store.UpdateMerchant(r.Context(), ses.merchant.ID, func(m *core.Merchant) error {
		m.SettlementAddress, m.SettlementRequestedAt = a.Lower(), s.now().UTC()
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not save the address")
		return
	}
	writeJSON(w, http.StatusOK, s.settlementView(r, m))
}

type keyView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func viewKey(k core.APIKey) keyView {
	return keyView{ID: k.ID, Name: k.Name, Prefix: k.Prefix, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt}
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request, ses session) {
	ks, err := s.Store.ListAPIKeys(r.Context(), ses.merchant.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list keys")
		return
	}
	out := make([]keyView, 0, len(ks))
	for _, k := range ks {
		out = append(out, viewKey(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request, ses session) {
	if strings.TrimSpace(ses.merchant.SettlementAddress) == "" {
		writeErr(w, http.StatusBadRequest, "a settlement destination wallet must be configured before generating API keys")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	plain, k, err := s.Store.CreateAPIKey(r.Context(), ses.merchant.ID, req.Name, s.now())
	if errors.Is(err, store.ErrInvalid) {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create a key")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"key": plain, "api_key": viewKey(k), "note": "Copy this key now; it will not be shown again."})
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request, ses session) {
	if err := s.Store.RevokeAPIKey(r.Context(), ses.merchant.ID, r.PathValue("id"), s.now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "key not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not revoke the key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

func limitParam(r *http.Request, def, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return def
	}
	return min(n, max)
}

func (s *Server) listIntents(w http.ResponseWriter, r *http.Request, ses session) {
	status := core.Status(r.URL.Query().Get("status"))
	switch status {
	case "", core.StatusPending, core.StatusPaid, core.StatusExpired:
	default:
		writeErr(w, http.StatusBadRequest, "status must be pending, paid or expired")
		return
	}
	items, next, err := s.Store.ListIntents(r.Context(), ses.merchant.ID, store.IntentFilter{Status: status, Limit: limitParam(r, 25, 100), After: r.URL.Query().Get("after")})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list payments")
		return
	}
	out := make([]core.IntentView, 0, len(items))
	for _, in := range items {
		out = append(out, in.View())
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out, "next": next})
}

type paymentView struct {
	TxHash      string `json:"tx_hash"`
	BlockNumber uint64 `json:"block_number"`
	From        string `json:"from"`
	Amount      string `json:"amount"`
}

func (s *Server) getIntent(w http.ResponseWriter, r *http.Request, ses session) {
	in, err := s.Store.GetIntent(r.Context(), r.PathValue("id"))
	if err != nil || in.MerchantID != ses.merchant.ID {
		writeErr(w, http.StatusNotFound, "payment not found")
		return
	}
	ps, _ := s.Store.IntentPayments(r.Context(), in.ID)
	pv := make([]paymentView, 0, len(ps))
	for _, p := range ps {
		pv = append(pv, paymentView{TxHash: p.TxHash, BlockNumber: p.BlockNumber, From: p.From, Amount: core.FormatUSDC(p.Amount)})
	}
	owed, _ := s.Store.OwedMicro(r.Context(), ses.merchant.ID, in.ID)
	jobs, _ := s.Store.ListSweepJobs(r.Context(), ses.merchant.ID, 100)
	var payouts []payoutView
	for _, j := range jobs {
		if j.IntentID == in.ID {
			payouts = append(payouts, viewPayout(j))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"payment": in.View(), "transfers": pv, "owed_to_you": core.FormatUSDC(owed), "payouts": payouts})
}

type payoutView struct {
	core.PayoutView
	IntentID  string     `json:"intent_id"`
	Reason    string     `json:"reason,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	Confirmed *time.Time `json:"confirmed_at,omitempty"`
}

func viewPayout(j core.SweepJob) payoutView {
	return payoutView{PayoutView: j.View(), IntentID: j.IntentID, Reason: j.Reason, CreatedAt: j.CreatedAt, Confirmed: j.ConfirmedAt}
}

func (s *Server) listPayouts(w http.ResponseWriter, r *http.Request, ses session) {
	jobs, err := s.Store.ListSweepJobs(r.Context(), ses.merchant.ID, limitParam(r, 25, 100))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list payouts")
		return
	}
	out := make([]payoutView, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, viewPayout(j))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request, ses session) {
	st, err := s.Store.MerchantStats(r.Context(), ses.merchant.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not load stats")
		return
	}
	f := core.FormatUSDC
	writeJSON(w, http.StatusOK, map[string]any{
		"payments": map[string]int{"total": st.Intents, "pending": st.Pending, "paid": st.Paid, "expired": st.Expired},
		"volume":   f(st.VolumeMicro), "platform_fees": f(st.FeesMicro),
		"awaiting_payout": f(st.PendingPayoutMicro), "paid_out": f(st.SettledMicro), "network_fees": f(st.NetworkFeesMicro),
		"payouts":  map[string]int{"confirmed": st.PayoutsConfirmed, "in_flight": st.PayoutsInFlight, "failed": st.PayoutsFailed},
		"currency": core.Currency,
	})
}

func (s *Server) deliveries(w http.ResponseWriter, r *http.Request, ses session) {
	ds, err := s.Store.ListDeliveries(r.Context(), ses.merchant.ID, limitParam(r, 25, 100))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list deliveries")
		return
	}
	type dv struct {
		EventID     string     `json:"event_id"`
		Type        string     `json:"type"`
		IntentID    string     `json:"intent_id,omitempty"`
		CreatedAt   time.Time  `json:"created_at"`
		Attempts    int        `json:"attempts"`
		DeliveredAt *time.Time `json:"delivered_at,omitempty"`
		Dead        bool       `json:"dead"`
		LastError   string     `json:"last_error,omitempty"`
	}
	out := make([]dv, 0, len(ds))
	for _, d := range ds {
		out = append(out, dv{d.Event.ID, d.Event.Type, d.Event.IntentID, d.Event.CreatedAt, d.Attempts, d.DeliveredAt, d.Dead, d.LastError})
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}
