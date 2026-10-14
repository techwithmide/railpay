package webhook

import (
	"arcpay/internal/core"
	"arcpay/internal/store"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func Sign(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", ts)
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

func Verify(secret, header string, body []byte, tolerance time.Duration, now time.Time) error {
	var ts int64
	var sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts, _ = strconv.ParseInt(v, 10, 64)
		case "v1":
			sig = v
		}
	}
	if ts == 0 || sig == "" {
		return errors.New("malformed signature header")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return errors.New("timestamp outside tolerance")
	}
	want, _ := hex.DecodeString(strings.TrimPrefix(Sign(secret, ts, body), fmt.Sprintf("t=%d,v1=", ts)))
	got, err := hex.DecodeString(sig)
	if err != nil || !hmac.Equal(want, got) {
		return errors.New("signature mismatch")
	}
	return nil
}

var backoffs = []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute,
	30 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour}

func Backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > len(backoffs) {
		return backoffs[len(backoffs)-1]
	}
	return backoffs[attempt-1]
}

func NewClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if !allowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() ||
				ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				return fmt.Errorf("webhook: blocked address %s", host)
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{DialContext: dialer.DialContext, Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type Dispatcher struct {
	Store       store.Store
	Client      *http.Client
	Workers     int
	Poll        time.Duration
	MaxAttempts int
	Log         *slog.Logger
	Now         func() time.Time
}

func NewDispatcher(st store.Store, client *http.Client, log *slog.Logger) *Dispatcher {
	return &Dispatcher{Store: st, Client: client, Workers: 8, Poll: 500 * time.Millisecond, MaxAttempts: 10, Log: log, Now: time.Now}
}

func (d *Dispatcher) Run(ctx context.Context) {
	for ctx.Err() == nil {
		n, err := d.RunOnce(ctx)
		if err != nil {
			d.Log.Error("webhook lease failed", "err", err)
		}
		if n == 0 || err != nil {
			select {
			case <-ctx.Done():
			case <-time.After(d.Poll):
			}
		}
	}
}

func (d *Dispatcher) RunOnce(ctx context.Context) (int, error) {
	batch, err := d.Store.LeaseDeliveries(ctx, d.Now(), d.Workers*4, 30*time.Second)
	if err != nil {
		return 0, err
	}
	sem := make(chan struct{}, d.Workers)
	var wg sync.WaitGroup
	for _, dl := range batch {
		wg.Add(1)
		sem <- struct{}{}
		go func(dl core.Delivery) {
			defer wg.Done()
			defer func() { <-sem }()
			d.deliver(ctx, dl)
		}(dl)
	}
	wg.Wait()
	return len(batch), nil
}

func (d *Dispatcher) deliver(ctx context.Context, dl core.Delivery) {
	now := d.Now()
	var sendErr error
	m, err := d.Store.MerchantByID(ctx, dl.Event.MerchantID)
	switch {
	case err != nil:
		sendErr = err
	case m.WebhookURL == "":
	default:
		sendErr = d.post(ctx, m, dl.Event, now)
	}

	res := store.DeliveryResult{At: now}
	if sendErr == nil {
		res.Delivered = true
	} else {
		attempt := dl.Attempts + 1
		res.Err = sendErr.Error()
		if attempt >= d.MaxAttempts {
			res.Dead = true
		} else {
			res.NextAttempt = now.Add(Backoff(attempt))
		}
		d.Log.Warn("webhook delivery failed", "event", dl.Event.ID, "attempt", attempt, "dead", res.Dead, "err", sendErr)
	}
	if err := d.Store.CompleteDelivery(ctx, dl.Event.ID, res); err != nil {
		d.Log.Error("recording delivery result failed", "event", dl.Event.ID, "err", err)
	}
}

func (d *Dispatcher) post(ctx context.Context, m core.Merchant, ev core.Event, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.WebhookURL, bytes.NewReader(ev.Payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "railpay-webhooks/1")
	req.Header.Set("Railpay-Event-Id", ev.ID)
	sig := Sign(m.WebhookSecret, now.Unix(), ev.Payload)
	req.Header.Set("Railpay-Signature", sig)
	req.Header.Set("Arcpay-Event-Id", ev.ID)
	req.Header.Set("Arcpay-Signature", sig)
	resp, err := d.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("endpoint returned %d", resp.StatusCode)
	}
	return nil
}
