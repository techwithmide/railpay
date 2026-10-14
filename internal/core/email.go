package core

import (
	"errors"
	"net/mail"
	"strings"
	"time"
)

const (
	EmailPaymentReceipt = "payment_receipt"
	EmailPayoutSent     = "payout_sent"
)

type Email struct {
	ID          string
	Key         string
	Kind        string
	To          string
	MerchantID  string
	IntentID    string
	Data        map[string]string
	CreatedAt   time.Time
	Attempts    int
	NextAttempt time.Time
	SentAt      *time.Time
	Dead        bool
	LastError   string
}

func ValidEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 254 || strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("invalid email address")
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" {
		return "", errors.New("invalid email address")
	}
	dom := s[strings.LastIndex(s, "@")+1:]
	if !strings.Contains(dom, ".") || strings.HasSuffix(dom, ".") || strings.HasPrefix(dom, ".") {
		return "", errors.New("invalid email address")
	}
	return s, nil
}

func reference(in *Intent) string {
	for _, k := range []string{"order_id", "reference", "invoice_id"} {
		if v := in.Metadata[k]; v != "" {
			return v
		}
	}
	return ""
}

func EmailsFor(ev Event, m Merchant, in *Intent, p *Payment, job *SweepJob, now time.Time) []Email {
	mk := func(kind, to string, data map[string]string) Email {
		return Email{ID: NewID("eml"), Key: "email:" + ev.ID + ":" + kind, Kind: kind, To: to, MerchantID: in.MerchantID, IntentID: in.ID, Data: data, CreatedAt: now, NextAttempt: now}
	}
	switch ev.Type {
	case EventSucceeded:
		if in.CustomerEmail == "" {
			return nil
		}
		d := map[string]string{
			"merchant_name": m.Name, "amount": FormatUSDC(in.Received), "currency": Currency, "intent_id": in.ID, "reference": reference(in), "paid_at": now.UTC().Format(time.RFC1123),
		}
		if p != nil {
			d["tx_hash"] = strings.ToLower(p.TxHash)
		}
		return []Email{mk(EmailPaymentReceipt, in.CustomerEmail, d)}
	case EventPayoutDone:
		if m.Email == "" || m.EmailOptOut || job == nil {
			return nil
		}
		return []Email{mk(EmailPayoutSent, m.Email, map[string]string{
			"merchant_name": m.Name, "amount": FormatUSDC(job.ValueMicro), "network_fee": FormatUSDC(job.ChargeMicro), "currency": Currency, "destination": job.Destination, "tx_hash": strings.ToLower(job.TxHash), "intent_id": in.ID,
			"reference": reference(in), "payout_amount": FormatUSDC(in.Received), "block": Itoa(job.BlockNumber),
		})}
	}
	return nil
}

func Itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
