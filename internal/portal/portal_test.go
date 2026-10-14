package portal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"arcpay/internal/core"
	"arcpay/internal/signer"
	"arcpay/internal/store"
)

type dummyRegistrar struct{}

func (d dummyRegistrar) RegisterDestination(ctx context.Context, merchantID, address, requestedBy string) (signer.Destination, error) {
	return signer.Destination{MerchantID: merchantID, Active: address}, nil
}

func (d dummyRegistrar) Destination(ctx context.Context, merchantID string) (signer.Destination, error) {
	return signer.Destination{MerchantID: merchantID, Active: "0x1111111111111111111111111111111111111111"}, nil
}

func setupPortalTest(_ *testing.T) (*Server, *store.Memory) {
	st := store.NewMemory()
	st.SeedMerchant(core.Merchant{ID: "mch_1", Name: "Test Merchant", Status: "active"}, "sk_test_key")
	srv := &Server{
		Store:             st,
		Registrar:         dummyRegistrar{},
		Providers:         map[string]Provider{},
		BaseURL:           "http://localhost:8080",
		StateSecret:       []byte("12345678901234567890123456789012"),
		PostLoginURL:      "/",
		SessionTTL:        time.Hour,
		AllowHTTPWebhooks: true,
	}
	return srv, st
}

func TestIndexReturnsJSON(t *testing.T) {
	srv, _ := setupPortalTest(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "RailPay API") || !strings.Contains(body, "online") {
		t.Fatalf("expected service info in root response: %s", body)
	}
}

func TestDevLoginAndDashboardAPI(t *testing.T) {
	srv, _ := setupPortalTest(t)
	handler := srv.Handler()

	loginReq := httptest.NewRequest("POST", "/auth/dev/login", nil)
	loginW := httptest.NewRecorder()
	handler.ServeHTTP(loginW, loginReq)

	if loginW.Code != http.StatusFound {
		t.Fatalf("dev login expected 302, got %d", loginW.Code)
	}
	cookie := loginW.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookie {
		if c.Name == "railpay_session" || c.Name == "arcpay_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected railpay_session cookie")
	}

	// 2. Fetch /api/me with session cookie
	meReq := httptest.NewRequest("GET", "/api/me", nil)
	meReq.AddCookie(sessionCookie)
	meW := httptest.NewRecorder()
	handler.ServeHTTP(meW, meReq)

	if meW.Code != http.StatusOK {
		t.Fatalf("api/me expected 200, got %d: %s", meW.Code, meW.Body.String())
	}
	body := meW.Body.String()
	if !strings.Contains(body, "Dev Merchant") || !strings.Contains(body, "dev@railpay.xyz") {
		t.Fatalf("api/me missing expected merchant details: %s", body)
	}

	// 3. Fetch /api/stats with session cookie
	statsReq := httptest.NewRequest("GET", "/api/stats", nil)
	statsReq.AddCookie(sessionCookie)
	statsW := httptest.NewRecorder()
	handler.ServeHTTP(statsW, statsReq)

	if statsW.Code != http.StatusOK {
		t.Fatalf("api/stats expected 200, got %d: %s", statsW.Code, statsW.Body.String())
	}
}

func TestPasswordSignUpAndLogin(t *testing.T) {
	srv, _ := setupPortalTest(t)
	handler := srv.Handler()

	// 1. Invalid email signup
	{
		body := `{"email": "not-an-email", "password": "validPassword123"}`
		req := httptest.NewRequest("POST", "/auth/signup", strings.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for bad email, got %d", w.Code)
		}
	}

	// 2. Short password signup
	{
		body := `{"email": "user@example.com", "password": "short"}`
		req := httptest.NewRequest("POST", "/auth/signup", strings.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for short password, got %d", w.Code)
		}
	}

	// 3. Valid signup
	var sessionCookie *http.Cookie
	{
		body := `{"email": "alice@example.com", "password": "SecurePassword123!", "name": "Alice Corp"}`
		req := httptest.NewRequest("POST", "/auth/signup", strings.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201 for valid signup, got %d: %s", w.Code, w.Body.String())
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == "railpay_session" {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil {
			t.Fatal("expected railpay_session cookie after signup")
		}
		respStr := w.Body.String()
		if !strings.Contains(respStr, `"ok":true`) || !strings.Contains(respStr, "Alice Corp") || !strings.Contains(respStr, "alice@example.com") {
			t.Fatalf("unexpected signup response body: %s", respStr)
		}
		if strings.Contains(respStr, "password_hash") {
			t.Fatalf("password hash leaked in response: %s", respStr)
		}
	}

	// 4. Duplicate signup rejected
	{
		body := `{"email": "alice@example.com", "password": "AnotherPassword456!"}`
		req := httptest.NewRequest("POST", "/auth/signup", strings.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusConflict {
			t.Fatalf("expected 409 for duplicate email, got %d", w.Code)
		}
	}

	// 5. Login with wrong password
	{
		body := `{"email": "alice@example.com", "password": "WrongPassword999"}`
		req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for wrong password, got %d", w.Code)
		}
	}

	// 6. Login with nonexistent email
	{
		body := `{"email": "nobody@example.com", "password": "SecurePassword123!"}`
		req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for nonexistent email, got %d", w.Code)
		}
	}

	// 7. Successful login
	var loginCookie *http.Cookie
	{
		body := `{"email": "alice@example.com", "password": "SecurePassword123!"}`
		req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for valid login, got %d: %s", w.Code, w.Body.String())
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == "railpay_session" {
				loginCookie = c
				break
			}
		}
		if loginCookie == nil {
			t.Fatal("expected railpay_session cookie after login")
		}
	}

	// 8. Access /api/me with login cookie
	{
		req := httptest.NewRequest("GET", "/api/me", nil)
		req.AddCookie(loginCookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 on /api/me, got %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "alice@example.com") {
			t.Fatalf("/api/me missing expected email: %s", w.Body.String())
		}
	}

	// 9. Logout clears session
	{
		req := httptest.NewRequest("POST", "/auth/logout", nil)
		req.AddCookie(loginCookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 on /auth/logout, got %d", w.Code)
		}

		// Subsequent /api/me should be rejected
		meReq := httptest.NewRequest("GET", "/api/me", nil)
		meReq.AddCookie(loginCookie)
		meW := httptest.NewRecorder()
		handler.ServeHTTP(meW, meReq)
		if meW.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on /api/me after logout, got %d", meW.Code)
		}
	}
}
