package main

import (
	"arcpay/internal/core"
	"arcpay/internal/signer"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadDotEnv(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if _, exists := os.LookupEnv(k); !exists {
			_ = os.Setenv(k, v)
		}
	}
}

func main() {
	loadDotEnv(".env")
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("signer failed to start", "err", err)
		os.Exit(1)
	}
}

func usdcWei(s string) (*big.Int, error) {
	m, err := core.ParseUSDC(s)
	if err != nil {
		return nil, fmt.Errorf("bad USDC amount %q: %w", s, err)
	}
	return core.MicroToNative(m), nil
}

func run(log *slog.Logger) error {
	dev := env("ARCPAY_ENV", "") == "dev"

	secret := os.Getenv("DERIVE_SECRET")
	if f := os.Getenv("DERIVE_SECRET_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		secret = strings.TrimSpace(string(b))
	}
	be, err := signer.NewLocalBackend(secret)
	if err != nil {
		return err
	}

	toks := signer.Tokens{
		signer.ScopeAddress: os.Getenv("SIGNER_TOKEN_ADDRESS"), signer.ScopeSign: os.Getenv("SIGNER_TOKEN_SIGN"),
		signer.ScopeRegister: os.Getenv("SIGNER_TOKEN_REGISTER"), signer.ScopeApprove: os.Getenv("SIGNER_TOKEN_APPROVE"),
	}
	seen := map[string]string{}
	for scope, t := range toks {
		if len(t) < 32 {
			return fmt.Errorf("SIGNER_TOKEN_%s must be at least 32 characters", strings.ToUpper(scope))
		}
		if other, dup := seen[t]; dup {
			return fmt.Errorf("the %s and %s tokens must be different: that separation is the point", scope, other)
		}
		seen[t] = scope
	}

	chainID, err := strconv.ParseUint(os.Getenv("CHAIN_ID"), 10, 64)
	if err != nil || chainID == 0 {
		return errors.New("CHAIN_ID is required (5042 mainnet, 5042002 testnet)")
	}
	maxValue, err := usdcWei(env("MAX_VALUE_USDC", "10000"))
	if err != nil {
		return err
	}
	daily, err := usdcWei(env("DAILY_CAP_USDC", "50000"))
	if err != nil {
		return err
	}
	global, err := usdcWei(env("GLOBAL_DAILY_CAP_USDC", "250000"))
	if err != nil {
		return err
	}
	feeGwei, err := strconv.ParseInt(env("MAX_FEE_GWEI", "1000"), 10, 64)
	if err != nil || feeGwei <= 0 {
		return errors.New("MAX_FEE_GWEI must be a positive integer")
	}
	cooldown := 24 * time.Hour
	approval := true
	if dev {
		cooldown, approval = 0, false
	}
	if v := os.Getenv("DESTINATION_COOLDOWN"); v != "" {
		if cooldown, err = time.ParseDuration(v); err != nil {
			return fmt.Errorf("DESTINATION_COOLDOWN: %w", err)
		}
	}
	if v := os.Getenv("REQUIRE_APPROVAL"); v != "" {
		if approval, err = strconv.ParseBool(v); err != nil {
			return fmt.Errorf("REQUIRE_APPROVAL: %w", err)
		}
	}
	if !dev && cooldown == 0 && !approval {
		return errors.New("refusing to run in production with neither a destination cool-down nor approval")
	}

	statePath := env("SIGNER_STATE_FILE", "signer-state.json")
	var restore *signer.State
	if b, err := os.ReadFile(statePath); err == nil {
		restore = new(signer.State)
		if err := json.Unmarshal(b, restore); err != nil {
			return fmt.Errorf("state file %s is corrupt: %w", statePath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	audit, err := os.OpenFile(env("SIGNER_AUDIT_FILE", "signer-audit.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer audit.Close()
	var auditMu sync.Mutex
	auditEnc := json.NewEncoder(audit)

	g, err := signer.NewGuard(signer.Config{
		ChainID: chainID, MaxValue: maxValue, DailyCap: daily, GlobalDailyCap: global,
		MaxFeeCap:           new(big.Int).Mul(big.NewInt(feeGwei), big.NewInt(1e9)),
		DestinationCooldown: cooldown, RequireApproval: approval,
		OnChange: func(s signer.State) {
			b, err := json.Marshal(s)
			if err == nil {
				err = writeAtomic(statePath, b)
			}
			if err != nil {
				log.Error("could not persist signer state", "err", err)
			}
		},
		AuditSink: func(r signer.AuditRecord) {
			auditMu.Lock()
			defer auditMu.Unlock()
			_ = auditEnc.Encode(r)
			_ = audit.Sync()
			if r.Outcome == "deny" || strings.HasPrefix(r.Action, "destination.") || r.Action == "freeze" {
				log.Warn("signer audit", "action", r.Action, "outcome", r.Outcome, "merchant", r.MerchantID, "detail", r.Detail)
			}
		},
	}, be, restore)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr: env("SIGNER_ADDR", "127.0.0.1:8081"), Handler: (&signer.Server{G: g, Tokens: toks}).Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second,
	}
	cert, key := os.Getenv("SIGNER_TLS_CERT"), os.Getenv("SIGNER_TLS_KEY")
	if ca := os.Getenv("SIGNER_CLIENT_CA"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("SIGNER_CLIENT_CA has no certificates")
		}
		srv.TLSConfig = &tls.Config{ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	errc := make(chan error, 1)
	go func() {
		log.Info("signer listening", "addr", srv.Addr, "chain_id", chainID, "tls", cert != "",
			"cooldown", cooldown.String(), "require_approval", approval, "restored_state", restore != nil)
		if cert != "" {
			errc <- srv.ListenAndServeTLS(cert, key)
		} else {
			if !dev {
				log.Warn("serving plain HTTP: put this behind mTLS or a private network")
			}
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case <-stop:
		return srv.Close()
	case err := <-errc:
		return err
	}
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
