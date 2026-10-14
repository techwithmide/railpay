package main

import (
	"arcpay/internal/api"
	"arcpay/internal/chain"
	"arcpay/internal/core"
	"arcpay/internal/notify"
	"arcpay/internal/portal"
	"arcpay/internal/reconcile"
	"arcpay/internal/settle"
	"arcpay/internal/signer"
	"arcpay/internal/store"
	"arcpay/internal/store/postgres"
	"arcpay/internal/watcher"
	"arcpay/internal/webhook"
	"context"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

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

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	loadDotEnv(".env")
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	fatal := func(msg string, args ...any) {
		log.Error(msg, args...)
		os.Exit(1)
	}
	dev := env("ARCPAY_ENV", "") == "dev"

	rpcURL := env("ARC_RPC_URL", "")
	if rpcURL == "" {
		fatal("ARC_RPC_URL is required")
	}
	baseURL := env("BASE_URL", "http://localhost:8080")
	rpc := &chain.Client{URL: rpcURL, HTTP: &http.Client{Timeout: 15 * time.Second}}

	startCtx, cancelStart := context.WithTimeout(context.Background(), 20*time.Second)
	chainID, err := rpc.ChainID(startCtx)
	cancelStart()
	if err != nil {
		fatal("could not read the chain ID from ARC_RPC_URL", "err", err)
	}
	log.Info("connected", "chain_id", chainID)

	var (
		addrSvc  api.AddressProvider
		signSvc  settle.Signer
		regSvc   portal.Registrar
		onHalt   func(string)
		devGuard *signer.Guard
	)
	if u := env("SIGNER_URL", ""); u != "" {
		for _, k := range []string{"SIGNER_TOKEN_ADDRESS", "SIGNER_TOKEN_SIGN", "SIGNER_TOKEN_REGISTER"} {
			if os.Getenv(k) == "" {
				fatal(k + " is required with SIGNER_URL")
			}
		}
		addrSvc = signer.NewClient(u, os.Getenv("SIGNER_TOKEN_ADDRESS"))
		signSvc = signer.NewClient(u, os.Getenv("SIGNER_TOKEN_SIGN"))
		regSvc = signer.NewClient(u, os.Getenv("SIGNER_TOKEN_REGISTER"))
	} else if dev && os.Getenv("DERIVE_SECRET") != "" {
		be, err := signer.NewLocalBackend(os.Getenv("DERIVE_SECRET"))
		if err != nil {
			fatal("bad DERIVE_SECRET", "err", err)
		}
		devGuard, err = signer.NewGuard(signer.Config{
			ChainID: chainID.Uint64(), MaxValue: core.MicroToNative(1_000_000 * 1_000_000), MaxFeeCap: new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e9)),
		}, be, nil)
		if err != nil {
			fatal("signer", "err", err)
		}
		addrSvc, signSvc, regSvc = devGuard, devGuard, devGuard
		onHalt = func(r string) { devGuard.Freeze(r, "reconciler") }
		log.Warn("DEV MODE: running an in-process signer. Never do this with real funds.")
	} else {
		fatal("set SIGNER_URL (and the SIGNER_TOKEN_* values), or ARCPAY_ENV=dev with DERIVE_SECRET for local testing")
	}

	bps, err := strconv.ParseUint(env("PLATFORM_FEE_BPS", "0"), 10, 32)
	if err != nil || bps > 5000 {
		fatal("PLATFORM_FEE_BPS must be 0-5000")
	}

	var st store.Store
	type seeder interface {
		SeedMerchant(mc core.Merchant, apiKey string)
	}

	if dsn := env("DATABASE_URL", ""); dsn != "" {
		pgStore, err := postgres.New(context.Background(), dsn, uint32(bps))
		if err != nil {
			fatal("could not connect to postgres database", "err", err)
		}
		st = pgStore
		log.Info("connected to persistent PostgreSQL store")
	} else {
		if !dev {
			log.Warn("DATABASE_URL is not set: running with in-memory store. State will be lost on restart!")
		}
		mem := store.NewMemory()
		mem.DefaultFeeBps = uint32(bps)
		st = mem
	}

	if dev {
		if key := os.Getenv("DEV_API_KEY"); key != "" {
			m := core.Merchant{ID: "mch_dev", Name: "Dev merchant", WebhookURL: os.Getenv("DEV_WEBHOOK_URL"), WebhookSecret: os.Getenv("DEV_WEBHOOK_SECRET")}
			if a := os.Getenv("DEV_SETTLEMENT_ADDRESS"); a != "" {
				if _, err := regSvc.RegisterDestination(context.Background(), m.ID, a, "dev"); err != nil {
					fatal("DEV_SETTLEMENT_ADDRESS", "err", err)
				}
				m.SettlementAddress = strings.ToLower(a)
			}
			if s, ok := st.(seeder); ok {
				s.SeedMerchant(m, key)
			}
		}
	}

	providers := map[string]portal.Provider{}
	if id := os.Getenv("GOOGLE_CLIENT_ID"); id != "" {
		providers["google"] = portal.Google(id, os.Getenv("GOOGLE_CLIENT_SECRET"))
	}
	if id := os.Getenv("GITHUB_CLIENT_ID"); id != "" {
		providers["github"] = portal.GitHub(id, os.Getenv("GITHUB_CLIENT_SECRET"))
	}
	stateSecret := env("STATE_SECRET", "")
	if len(providers) > 0 && len(stateSecret) < 32 {
		fatal("STATE_SECRET (at least 32 characters) is required when OAuth providers are configured")
	}
	var origins []string
	for _, o := range strings.Split(env("ALLOWED_ORIGINS", ""), ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}

	minPayout, err := core.ParseUSDC(env("MIN_PAYOUT_USDC", "0.01"))
	if err != nil {
		fatal("MIN_PAYOUT_USDC", "err", err)
	}
	startBlock, _ := strconv.ParseUint(env("START_BLOCK", "0"), 10, 64)

	w := watcher.New(watcher.Config{StartBlock: startBlock}, rpc, st, log)
	disp := webhook.NewDispatcher(st, webhook.NewClient(dev), log)
	sw := settle.New(settle.Config{ChainID: chainID.Uint64(), MinPayoutMicro: minPayout}, rpc, signSvc, st, log)
	rec := reconcile.New(reconcile.Config{OnHalt: onHalt}, rpc, st, log)

	var emailSender notify.Sender = notify.LogSender{Log: log}
	if smtpHost := env("SMTP_HOST", ""); smtpHost != "" {
		emailSender = &notify.SMTPSender{
			Host: smtpHost, Port: env("SMTP_PORT", "587"),
			Username: env("SMTP_USER", ""), Password: env("SMTP_PASS", ""),
			From: env("SMTP_FROM", "billing@railpay.xyz"), Timeout: 25 * time.Second,
			AllowPlaintext: dev,
		}
		log.Info("email notifications enabled via SMTP", "host", smtpHost)
	} else {
		log.Info("email notifications in dev mode (logging to stdout)")
	}
	emailWorker := &notify.Worker{
		Store:  st,
		Sender: emailSender,
		Render: notify.RenderConfig{
			Brand:       env("BRAND_NAME", "RailPay"),
			ExplorerURL: env("EXPLORER_URL", "https://testnet.arcscan.io"),
		},
		Log: log,
	}

	apiH := (&api.Server{Store: st, Addresses: addrSvc, BaseURL: baseURL}).Handler()
	portalH := (&portal.Server{
		Store: st, Registrar: regSvc, Providers: providers, BaseURL: baseURL, StateSecret: []byte(stateSecret),
		PostLoginURL: env("DASHBOARD_URL", "/"), CookieInsecure: env("COOKIE_INSECURE", "") == "true",
		AllowedOrigins: origins, AllowHTTPWebhooks: dev,
	}).Handler()
	mux := http.NewServeMux()
	mux.Handle("/v1/", apiH)
	mux.Handle("/pay/", apiH)
	mux.Handle("/healthz", apiH)
	mux.Handle("/", portalH)

	var rootHandler http.Handler = mux
	if len(origins) > 0 {
		rootHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				for _, o := range origins {
					if o == origin || o == "*" {
						w.Header().Set("Access-Control-Allow-Origin", origin)
						w.Header().Set("Access-Control-Allow-Credentials", "true")
						w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, Idempotency-Key")
						w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
						w.Header().Add("Vary", "Origin")
						break
					}
				}
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			mux.ServeHTTP(w, r)
		})
	}
	srv := &http.Server{Addr: env("ARCPAY_ADDR", ":8080"), Handler: rootHandler, ReadHeaderTimeout: 5 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go w.Run(ctx)
	go disp.Run(ctx)
	go sw.Run(ctx)
	go rec.Run(ctx)
	go emailWorker.Run(ctx)
	go func() {
		log.Info("listening", "addr", srv.Addr, "dev", dev, "oauth_providers", len(providers))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal("http server failed", "err", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
