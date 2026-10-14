package notify

import (
	"arcpay/internal/store"
	"context"
	"errors"
	"log/slog"
	"time"
)

var backoffs = []time.Duration{30 * time.Second, 2 * time.Minute, 10 * time.Minute, time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour}

type Worker struct {
	Store       store.Store
	Sender      Sender
	Render      RenderConfig
	Log         *slog.Logger
	Batch       int
	Poll        time.Duration
	MaxAttempts int
	Now         func() time.Time
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Worker) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.Default()
}

func (w *Worker) Run(ctx context.Context) {
	poll := w.Poll
	if poll == 0 {
		poll = 2 * time.Second
	}
	for ctx.Err() == nil {
		n, err := w.RunOnce(ctx)
		if err != nil {
			w.log().Error("email outbox failed", "err", err)
		}
		if err != nil || n == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(poll):
			}
		}
	}
}

func (w *Worker) RunOnce(ctx context.Context) (int, error) {
	batch := w.Batch
	if batch == 0 {
		batch = 20
	}
	max := w.MaxAttempts
	if max == 0 {
		max = 8
	}
	es, err := w.Store.LeaseEmails(ctx, w.now(), batch, 2*time.Minute)
	if err != nil {
		return 0, err
	}
	for _, e := range es {
		msg, err := Render(e, w.Render)
		if err == nil {
			sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err = w.Sender.Send(sctx, msg)
			cancel()
		}
		now := w.now()
		res := store.EmailResult{At: now}
		attempt := e.Attempts + 1
		switch {
		case err == nil:
			res.Sent = true
		case errors.Is(err, ErrPermanent) || attempt >= max:
			res.Dead, res.Err = true, err.Error()
		default:
			res.Err = err.Error()
			res.NextAttempt = now.Add(backoffs[min(attempt, len(backoffs))-1])
		}
		if cerr := w.Store.CompleteEmail(ctx, e.ID, res); cerr != nil {
			w.log().Error("could not record email result", "email", e.ID, "err", cerr)
		}
		if err != nil {
			w.log().Warn("email send failed", "email", e.ID, "kind", e.Kind, "attempt", attempt, "dead", res.Dead, "err", err)
		}
	}
	return len(es), nil
}
