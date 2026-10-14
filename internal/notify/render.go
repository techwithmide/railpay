package notify

import (
	"arcpay/internal/core"
	"arcpay/internal/sweep/plan"
	"bytes"
	"errors"
	"fmt"
	htmpl "html/template"
	"strings"
	ttmpl "text/template"
	"unicode"
)

type RenderConfig struct {
	Brand       string
	ExplorerURL string
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

type view struct {
	core.Email
	D        map[string]string
	Brand    string
	TxURL    string
	Short    string
	Ref      string
	Merchant string
}

func shorten(a string) string {
	if len(a) > 14 {
		return a[:8] + "-" + a[len(a)-6:]
	}
	return a
}

const (
	fontStack = `-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif`
	lblStyle  = `padding:12px 0;border-top:1px solid #eef0f3;color:#6b7280;font-size:13px;width:38%;vertical-align:top`
	valStyle  = `padding:12px 0;border-top:1px solid #eef0f3;color:#111827;font-size:14px;text-align:right;vertical-align:top;word-break:break-all`
)

const layoutTop = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>{{.Brand}}</title>
</head>
<body style="margin:0;padding:0;background:#f4f5f7;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">%PREHEADER%</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f4f5f7;">
<tr><td align="center" style="padding:32px 16px;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:520px;">
    <tr><td style="padding:0 4px 16px;font-family:` + fontStack + `;font-size:15px;font-weight:700;letter-spacing:.2px;color:#111827;">{{.Brand}}</td></tr>
    <tr><td style="background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;padding:32px 28px;font-family:` + fontStack + `;">
`

const layoutBottom = `
    </td></tr>
    <tr><td style="padding:20px 8px 0;font-family:` + fontStack + `;font-size:12px;line-height:18px;color:#9ca3af;text-align:center;">%FOOTER%</td></tr>
  </table>
</td></tr>
</table>
</body></html>`

func layout(accentBg, accentFg, preheader, footer, body string) string {
	top := strings.NewReplacer(
		"%ACCENT_BG%", accentBg,
		"%ACCENT_FG%", accentFg,
		"%PREHEADER%", preheader,
	).Replace(layoutTop)
	bottom := strings.NewReplacer("%FOOTER%", footer).Replace(layoutBottom)
	return top + body + bottom
}

const badge = `<span style="display:inline-block;background:%ACCENT_BG%;color:%ACCENT_FG%;font-size:12px;font-weight:600;padding:4px 10px;border-radius:999px;">%LABEL%</span>`

const txButton = `{{if .TxURL}}
<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0 0;width:100%;"><tr><td align="center" style="border-radius:10px;background:#111827;">
<a href="{{.TxURL}}" style="display:block;padding:13px 20px;font-family:` + fontStack + `;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:10px;">View transaction</a>
</td></tr></table>
{{end}}`

var textTmpls = map[string]*ttmpl.Template{
	core.EmailPaymentReceipt: ttmpl.Must(ttmpl.New("r").Parse(`PAYMENT RECEIVED

{{.D.amount}} {{.D.currency}} paid to {{.Merchant}}

{{if .Ref}}Reference:   {{.Ref}}
{{end}}Payment ID:  {{.D.intent_id}}
Date:        {{.D.paid_at}}
{{if .TxURL}}Transaction: {{.TxURL}}
{{else if .D.tx_hash}}Transaction: {{.D.tx_hash}}
{{end}}
Keep this email as your receipt. If you did not make this payment, contact {{.Merchant}}.

Sent by {{.Brand}} on behalf of {{.Merchant}}.
`)),
	core.EmailPayoutSent: ttmpl.Must(ttmpl.New("p").Parse(`PAYOUT SENT

{{.D.amount}} {{.D.currency}} was sent to your settlement wallet.

For payment: {{if .Ref}}{{.Ref}}{{else}}{{.D.intent_id}}{{end}} ({{.D.payment_amount}} {{.D.currency}} received)
Network fee: {{.D.network_fee}} {{.D.currency}}
Wallet:      {{.D.destination}}
{{if .TxURL}}Transaction: {{.TxURL}}
{{else}}Transaction: {{.D.tx_hash}}
{{end}}
You are receiving this because payout emails are on for {{.Merchant}}. You can turn them off in your dashboard settings.

{{.Brand}}
`)),
}

var htmlTmpls = map[string]*htmpl.Template{
	core.EmailPaymentReceipt: htmpl.Must(htmpl.New("r").Parse(layout(
		"#dcfce7", "#166534",
		"{{.D.amount}} {{.D.currency}} paid to {{.Merchant}}",
		"Sent by {{.Brand}} on behalf of {{.Merchant}}.",
		strings.NewReplacer("%ACCENT_BG%", "#dcfce7", "%ACCENT_FG%", "#166534", "%LABEL%", "Payment received").Replace(badge)+`
<div style="font-size:40px;line-height:46px;font-weight:700;letter-spacing:-.5px;color:#111827;margin:18px 0 4px;">{{.D.amount}} <span style="font-size:20px;font-weight:600;color:#6b7280;">{{.D.currency}}</span></div>
<div style="font-size:15px;color:#4b5563;margin:0 0 24px;">Paid to <strong style="color:#111827;">{{.Merchant}}</strong></div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
{{if .Ref}}<tr><td style="`+lblStyle+`">Reference</td><td style="`+valStyle+`">{{.Ref}}</td></tr>{{end}}
<tr><td style="`+lblStyle+`">Payment ID</td><td style="`+valStyle+`">{{.D.intent_id}}</td></tr>
<tr><td style="`+lblStyle+`">Date</td><td style="`+valStyle+`">{{.D.paid_at}}</td></tr>
{{if .TxURL}}<tr><td style="`+lblStyle+`">Transaction</td><td style="`+valStyle+`;font-family:ui-monospace,Menlo,Consolas,monospace;">{{.Short}}</td></tr>
{{else if .D.tx_hash}}<tr><td style="`+lblStyle+`">Transaction</td><td style="`+valStyle+`;font-family:ui-monospace,Menlo,Consolas,monospace;">{{.D.tx_hash}}</td></tr>{{end}}
</table>
`+txButton+`
<p style="margin:24px 0 0;font-size:13px;line-height:20px;color:#6b7280;">Keep this email as your receipt. If you did not make this payment, contact {{.Merchant}}.</p>`,
	))),

	core.EmailPayoutSent: htmpl.Must(htmpl.New("p").Parse(layout(
		"#dbeafe", "#1e40af",
		"{{.D.amount}} {{.D.currency}} was sent to your settlement wallet",
		"You are receiving this because payout emails are on for {{.Merchant}}.<br>You can turn them off in your dashboard settings.",
		strings.NewReplacer("%ACCENT_BG%", "#dbeafe", "%ACCENT_FG%", "#1e40af", "%LABEL%", "Payout sent").Replace(badge)+`
<div style="font-size:40px;line-height:46px;font-weight:700;letter-spacing:-.5px;color:#111827;margin:18px 0 4px;">{{.D.amount}} <span style="font-size:20px;font-weight:600;color:#6b7280;">{{.D.currency}}</span></div>
<div style="font-size:15px;color:#4b5563;margin:0 0 24px;">was sent to your settlement wallet.</div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
<tr><td style="`+lblStyle+`">For payment</td><td style="`+valStyle+`">{{if .Ref}}{{.Ref}}{{else}}{{.D.intent_id}}{{end}}<br><span style="color:#6b7280;font-size:12px;">{{.D.payment_amount}} {{.D.currency}} received</span></td></tr>
<tr><td style="`+lblStyle+`">Network fee</td><td style="`+valStyle+`">{{.D.network_fee}} {{.D.currency}}</td></tr>
<tr><td style="`+lblStyle+`">Wallet</td><td style="`+valStyle+`;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;">{{.D.destination}}</td></tr>
{{if .TxURL}}<tr><td style="`+lblStyle+`">Transaction</td><td style="`+valStyle+`;font-family:ui-monospace,Menlo,Consolas,monospace;">{{.Short}}</td></tr>
{{else if .D.tx_hash}}<tr><td style="`+lblStyle+`">Transaction</td><td style="`+valStyle+`;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;">{{.D.tx_hash}}</td></tr>{{end}}
</table>
`+txButton,
	))),
}

func Render(e core.Email, cfg RenderConfig) (Message, error) {
	tt, ok := textTmpls[e.Kind]
	if !ok {
		return Message{}, fmt.Errorf("%w: unknown email kind %q", ErrPermanent, e.Kind)
	}
	brand := cfg.Brand
	if brand == "" {
		brand = "RailPay"
	}
	merchant := oneLine(e.Data["merchant_name"])
	if merchant == "" {
		merchant = "the merchant"
	}
	v := view{Email: e, D: e.Data, Brand: brand, Merchant: merchant, Ref: oneLine(e.Data["reference"])}
	if h := e.Data["tx_hash"]; h != "" {
		v.TxURL = plan.TxURL(cfg.ExplorerURL, h)
		v.Short = shorten(h)
	}
	var tb, hb bytes.Buffer
	if err := tt.Execute(&tb, v); err != nil {
		return Message{}, err
	}
	if err := htmlTmpls[e.Kind].Execute(&hb, v); err != nil {
		return Message{}, err
	}
	var subject string
	switch e.Kind {
	case core.EmailPaymentReceipt:
		subject = fmt.Sprintf("Receipt: %s %s paid to %s", e.Data["amount"], e.Data["currency"], merchant)
	case core.EmailPayoutSent:
		subject = fmt.Sprintf("Payout sent: %s %s to your wallet", e.Data["amount"], e.Data["currency"])
	}
	if e.To == "" {
		return Message{}, errors.New("email has no recipient")
	}
	return Message{To: e.To, Subject: oneLine(subject), Text: tb.String(), HTML: hb.String()}, nil
}
