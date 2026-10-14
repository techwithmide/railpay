package notify

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

type Sender interface {
	Send(ctx context.Context, m Message) error
}

var ErrPermanent = errors.New("permanent email failure")

type LogSender struct{ Log *slog.Logger }

func (l LogSender) Send(_ context.Context, m Message) error {
	l.Log.Info("email (not sent: no SMTP configured)", "to", m.To, "subject", m.Subject, "text", m.Text)
	return nil
}

type SMTPSender struct {
	Host, Port, Username, Password string
	From                           string
	Timeout                        time.Duration
	AllowPlaintext                 bool
}

func clean(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("control characters in header value")
	}
	return s, nil
}

func (s *SMTPSender) build(m Message) (from, to string, data []byte, err error) {
	fa, err := mail.ParseAddress(s.From)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid From address: %w", err)
	}
	ta, err := mail.ParseAddress(m.To)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: invalid recipient: %v", ErrPermanent, err)
	}
	subj, err := clean(m.Subject)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: %v", ErrPermanent, err)
	}
	domain := fa.Address[strings.LastIndex(fa.Address, "@")+1:]
	var rb [12]byte
	_, _ = rand.Read(rb[:])
	id := hex.EncodeToString(rb[:])
	boundary := "railpay-" + id

	var b strings.Builder
	h := func(k, v string) { b.WriteString(k); b.WriteString(": "); b.WriteString(v); b.WriteString("\r\n") }
	h("From", fa.String())
	h("To", ta.String())
	h("Subject", mime.QEncoding.Encode("utf-8", subj))
	h("Date", time.Now().UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+id+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Auto-Submitted", "auto-generated")
	h("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	part := func(ctype, body string) {
		b.WriteString("--")
		b.WriteString(boundary)
		b.WriteString("\r\n")
		b.WriteString("Content-Type: ")
		b.WriteString(ctype)
		b.WriteString("; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
		w := quotedprintable.NewWriter(&b)
		_, _ = w.Write([]byte(body))
		_ = w.Close()
		b.WriteString("\r\n")
	}
	part("text/plain", m.Text)
	if m.HTML != "" {
		part("text/html", m.HTML)
	}
	b.WriteString("--")
	b.WriteString(boundary)
	b.WriteString("--\r\n")
	return fa.Address, ta.Address, []byte(b.String()), nil
}

func (s *SMTPSender) Send(ctx context.Context, m Message) error {
	from, to, data, err := s.build(m)
	if err != nil {
		return err
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr := net.JoinHostPort(s.Host, s.Port)

	var conn net.Conn
	if s.Port == "465" {
		conn, err = (&tls.Dialer{NetDialer: &d, Config: &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}}).DialContext(dctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(dctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()

	if s.Port != "465" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return err
			}
		} else if !s.AllowPlaintext {
			return errors.New("SMTP server does not offer STARTTLS; refusing to send unencrypted")
		}
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return classify(err)
		}
	}
	if err := c.Mail(from); err != nil {
		return classify(err)
	}
	if err := c.Rcpt(to); err != nil {
		return classify(err)
	}
	w, err := c.Data()
	if err != nil {
		return classify(err)
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return classify(err)
	}
	return c.Quit()
}

func classify(err error) error {
	var te *textproto.Error
	if errors.As(err, &te) && te.Code >= 500 {
		return fmt.Errorf("%w: %v", ErrPermanent, err)
	}
	return err
}
