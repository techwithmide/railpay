package store

import (
	"arcpay/internal/core"
	"arcpay/internal/ledger"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxAPIKeysPerMerchant = 20

type Memory struct {
	mu            sync.Mutex
	book          *ledger.Book
	DefaultFeeBps uint32
	merchants     map[string]*core.Merchant
	users         map[string]*core.User
	userByIdent   map[string]string
	keys          map[string]*core.APIKey
	keyByHash     map[string]string
	sessions      map[string]*core.Session
	intents       map[string]*core.Intent
	byAddr        map[string]string
	idem          map[string]string
	payments      map[string][]core.Payment
	deliveries    map[string]*core.Delivery
	emails        map[string]*core.Email
	jobs          map[string]*core.SweepJob
	activeJob     map[string]string
	cursor        uint64
	cursorSet     bool
}

func NewMemory() *Memory {
	return &Memory{
		book:      ledger.NewBook(),
		merchants: map[string]*core.Merchant{}, users: map[string]*core.User{}, userByIdent: map[string]string{},
		keys: map[string]*core.APIKey{}, keyByHash: map[string]string{}, sessions: map[string]*core.Session{},
		intents: map[string]*core.Intent{}, byAddr: map[string]string{}, idem: map[string]string{},
		payments: map[string][]core.Payment{}, deliveries: map[string]*core.Delivery{}, emails: map[string]*core.Email{},
		jobs: map[string]*core.SweepJob{}, activeJob: map[string]string{},
	}
}

func (m *Memory) Ledger() *ledger.Book { return m.book }

func (m *Memory) SeedMerchant(mc core.Merchant, apiKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mc.Status == "" {
		mc.Status = "active"
	}
	if mc.CreatedAt.IsZero() {
		mc.CreatedAt = time.Now().UTC()
	}
	c := mc
	m.merchants[mc.ID] = &c
	if apiKey != "" {
		h := hashSecret(apiKey)
		id := core.NewID("key")
		m.keys[id] = &core.APIKey{ID: id, MerchantID: mc.ID, Name: "seed", Prefix: prefixOf(apiKey), Hash: h, CreatedAt: mc.CreatedAt}
		m.keyByHash[h] = id
	}
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func prefixOf(key string) string {
	if len(key) > 12 {
		return key[:12]
	}
	return key
}

func randomToken(prefix string, nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

func (m *Memory) MerchantByID(_ context.Context, id string) (core.Merchant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mc, ok := m.merchants[id]
	if !ok {
		return core.Merchant{}, ErrNotFound
	}
	return *mc, nil
}

func (m *Memory) MerchantByAPIKey(_ context.Context, key string) (core.Merchant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.keyByHash[hashSecret(key)]
	if !ok {
		return core.Merchant{}, ErrNotFound
	}
	k := m.keys[id]
	mc := m.merchants[k.MerchantID]
	if k.RevokedAt != nil || mc == nil || mc.Status != "active" {
		return core.Merchant{}, ErrNotFound
	}
	if now := time.Now().UTC(); k.LastUsedAt == nil || now.Sub(*k.LastUsedAt) > time.Minute {
		k.LastUsedAt = &now
	}
	return *mc, nil
}

func (m *Memory) UpdateMerchant(_ context.Context, id string, fn func(*core.Merchant) error) (core.Merchant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mc, ok := m.merchants[id]
	if !ok {
		return core.Merchant{}, ErrNotFound
	}
	c := *mc
	if err := fn(&c); err != nil {
		return core.Merchant{}, err
	}
	c.ID, c.CreatedAt = mc.ID, mc.CreatedAt
	*mc = c
	return c, nil
}

func (m *Memory) LoginUser(_ context.Context, p LoginProfile, now time.Time) (core.User, core.Merchant, bool, error) {
	if p.Provider == "" || p.Subject == "" {
		return core.User{}, core.Merchant{}, false, fmt.Errorf("%w: provider and subject are required", ErrInvalid)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ident := p.Provider + "|" + p.Subject
	if uid, ok := m.userByIdent[ident]; ok {
		u := m.users[uid]
		mc := m.merchants[u.MerchantID]
		if mc == nil || mc.Status != "active" {
			return core.User{}, core.Merchant{}, false, fmt.Errorf("%w: account suspended", ErrNotFound)
		}
		return *u, *mc, false, nil
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		name, _, _ = strings.Cut(p.Email, "@")
	}
	if name == "" {
		name = "My business"
	}
	mc := &core.Merchant{
		ID: core.NewID("mch"), Name: name, Email: p.Email, Status: "active", FeeBps: m.DefaultFeeBps,
		WebhookSecret: randomToken("whsec_", 24), CreatedAt: now.UTC(),
	}
	u := &core.User{ID: core.NewID("usr"), Provider: p.Provider, Subject: p.Subject, Email: p.Email, Name: p.Name, MerchantID: mc.ID, CreatedAt: now.UTC()}
	m.merchants[mc.ID] = mc
	m.users[u.ID] = u
	m.userByIdent[ident] = u.ID
	return *u, *mc, true, nil
}

func (m *Memory) SignUpPassword(_ context.Context, email, passwordHash, name string, now time.Time) (core.User, core.Merchant, error) {
	cleanEmail, err := core.ValidEmail(email)
	if err != nil {
		return core.User{}, core.Merchant{}, fmt.Errorf("%w: invalid email address", ErrInvalid)
	}
	email = cleanEmail
	if passwordHash == "" {
		return core.User{}, core.Merchant{}, fmt.Errorf("%w: password required", ErrInvalid)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, u := range m.users {
		if strings.EqualFold(u.Email, email) {
			return core.User{}, core.Merchant{}, fmt.Errorf("%w: an account with this email already exists", ErrDuplicate)
		}
	}

	name = strings.TrimSpace(name)
	if name == "" {
		name, _, _ = strings.Cut(email, "@")
	}
	if name == "" {
		name = "My business"
	}

	mc := &core.Merchant{
		ID:            core.NewID("mch"),
		Name:          name,
		Email:         email,
		Status:        "active",
		FeeBps:        m.DefaultFeeBps,
		WebhookSecret: randomToken("whsec_", 24),
		CreatedAt:     now.UTC(),
	}
	u := &core.User{
		ID:           core.NewID("usr"),
		Provider:     "password",
		Subject:      strings.ToLower(email),
		Email:        email,
		Name:         name,
		MerchantID:   mc.ID,
		PasswordHash: passwordHash,
		CreatedAt:    now.UTC(),
	}

	m.merchants[mc.ID] = mc
	m.users[u.ID] = u
	ident := u.Provider + "|" + u.Subject
	m.userByIdent[ident] = u.ID

	plainKey := randomToken("sk_live_", 32)
	h := hashSecret(plainKey)
	k := &core.APIKey{
		ID:         core.NewID("key"),
		MerchantID: mc.ID,
		Name:       "Default Key",
		Prefix:     prefixOf(plainKey),
		Hash:       h,
		CreatedAt:  now.UTC(),
	}
	m.keys[k.ID] = k
	m.keyByHash[h] = k.ID

	return *u, *mc, nil
}

func (m *Memory) AuthenticatePassword(_ context.Context, email string) (core.User, core.Merchant, string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return core.User{}, core.Merchant{}, "", fmt.Errorf("%w: email required", ErrInvalid)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var matched *core.User
	for _, u := range m.users {
		if strings.EqualFold(u.Email, email) && u.PasswordHash != "" {
			if matched == nil || u.CreatedAt.After(matched.CreatedAt) {
				matched = u
			}
		}
	}
	if matched == nil {
		return core.User{}, core.Merchant{}, "", ErrNotFound
	}

	mc, ok := m.merchants[matched.MerchantID]
	if !ok || mc == nil || mc.Status != "active" {
		return core.User{}, core.Merchant{}, "", fmt.Errorf("%w: account suspended", ErrNotFound)
	}

	return *matched, *mc, matched.PasswordHash, nil
}

func (m *Memory) UserByID(_ context.Context, id string) (core.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return core.User{}, ErrNotFound
	}
	return *u, nil
}

func (m *Memory) CreateAPIKey(_ context.Context, merchantID, name string, now time.Time) (string, core.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.merchants[merchantID]; !ok {
		return "", core.APIKey{}, ErrNotFound
	}
	active := 0
	for _, k := range m.keys {
		if k.MerchantID == merchantID && k.RevokedAt == nil {
			active++
		}
	}
	if active >= maxAPIKeysPerMerchant {
		return "", core.APIKey{}, fmt.Errorf("%w: at most %d active API keys", ErrInvalid, maxAPIKeysPerMerchant)
	}
	name = strings.TrimSpace(name)
	if len(name) > 60 {
		return "", core.APIKey{}, fmt.Errorf("%w: key name too long", ErrInvalid)
	}
	plain := randomToken("sk_live_", 32)
	k := &core.APIKey{ID: core.NewID("key"), MerchantID: merchantID, Name: name, Prefix: prefixOf(plain), Hash: hashSecret(plain), CreatedAt: now.UTC()}
	m.keys[k.ID] = k
	m.keyByHash[k.Hash] = k.ID
	return plain, *k, nil
}

func (m *Memory) ListAPIKeys(_ context.Context, merchantID string) ([]core.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []core.APIKey
	for _, k := range m.keys {
		if k.MerchantID == merchantID {
			out = append(out, *k)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt) || (out[i].CreatedAt.Equal(out[j].CreatedAt) && out[i].ID < out[j].ID)
	})
	return out, nil
}

func (m *Memory) RevokeAPIKey(_ context.Context, merchantID, keyID string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[keyID]
	if !ok || k.MerchantID != merchantID {
		return ErrNotFound
	}
	if k.RevokedAt == nil {
		t := now.UTC()
		k.RevokedAt = &t
	}
	return nil
}

func (m *Memory) CreateSession(_ context.Context, userID, merchantID string, ttl time.Duration, now time.Time) (string, core.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	token := randomToken("ses_", 32)
	s := &core.Session{ID: hashSecret(token), UserID: userID, MerchantID: merchantID, CSRF: randomToken("", 24), CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(ttl)}
	m.sessions[s.ID] = s

	for id, o := range m.sessions {
		if now.After(o.ExpiresAt) {
			delete(m.sessions, id)
		}
	}
	return token, *s, nil
}

func (m *Memory) SessionByToken(_ context.Context, token string, now time.Time) (core.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hashSecret(token)]
	if !ok {
		return core.Session{}, ErrNotFound
	}
	if now.After(s.ExpiresAt) {
		delete(m.sessions, s.ID)
		return core.Session{}, ErrNotFound
	}
	if mc := m.merchants[s.MerchantID]; mc == nil || mc.Status != "active" {
		return core.Session{}, ErrNotFound
	}
	return *s, nil
}

func (m *Memory) DeleteSession(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, hashSecret(token))
	return nil
}

func (m *Memory) CreateIntent(_ context.Context, in *core.Intent, idemKey string) (*core.Intent, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idemKey != "" {
		if id, ok := m.idem[in.MerchantID+":"+idemKey]; ok {
			return m.intents[id].Clone(), false, nil
		}
	}
	if _, dup := m.byAddr[in.DepositAddress]; dup {
		return nil, false, errors.New("deposit address collision")
	}
	m.intents[in.ID] = in.Clone()
	m.byAddr[in.DepositAddress] = in.ID
	if idemKey != "" {
		m.idem[in.MerchantID+":"+idemKey] = in.ID
	}
	return in.Clone(), true, nil
}

func (m *Memory) GetIntent(_ context.Context, id string) (*core.Intent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.intents[id]
	if !ok {
		return nil, ErrNotFound
	}
	return in.Clone(), nil
}

func (m *Memory) ListIntents(_ context.Context, merchantID string, f IntentFilter) ([]*core.Intent, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []*core.Intent
	for _, in := range m.intents {
		if in.MerchantID == merchantID && (f.Status == "" || in.Status == f.Status) {
			all = append(all, in)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.After(all[j].CreatedAt)
		}
		return all[i].ID > all[j].ID
	})
	start := 0
	if f.After != "" {
		start = len(all)
		for i, in := range all {
			if in.ID == f.After {
				start = i + 1
				break
			}
		}
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	end := min(start+limit, len(all))
	out := make([]*core.Intent, 0, end-start)
	for _, in := range all[start:end] {
		out = append(out, in.Clone())
	}
	next := ""
	if end < len(all) && len(out) > 0 {
		next = out[len(out)-1].ID
	}
	return out, next, nil
}

func (m *Memory) IntentPayments(_ context.Context, intentID string) ([]core.Payment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.intents[intentID]; !ok {
		return nil, ErrNotFound
	}
	return append([]core.Payment(nil), m.payments[intentID]...), nil
}

func (m *Memory) WatchedAddresses(_ context.Context, now time.Time, late time.Duration) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, in := range m.intents {
		switch in.Status {
		case core.StatusPending:
			out = append(out, in.DepositAddress)
		case core.StatusExpired:
			if now.Before(in.ExpiresAt.Add(late)) {
				out = append(out, in.DepositAddress)
			}
		case core.StatusPaid:
			if in.PaidAt != nil && now.Before(in.PaidAt.Add(late)) {
				out = append(out, in.DepositAddress)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *Memory) enqueue(ev core.Event, now time.Time) {
	m.deliveries[ev.ID] = &core.Delivery{Event: ev, NextAttempt: now}
}

func (m *Memory) enqueueEmailsLocked(ev core.Event, in *core.Intent, p *core.Payment, job *core.SweepJob, now time.Time) {
	var mc core.Merchant
	if x := m.merchants[in.MerchantID]; x != nil {
		mc = *x
	}
	for _, e := range core.EmailsFor(ev, mc, in, p, job, now) {
		if _, dup := m.emails[e.Key]; dup {
			continue
		}
		e := e
		m.emails[e.Key] = &e
	}
}

func feeOf(amount uint64, bps uint32) uint64 {
	hi, lo := bits.Mul64(amount, uint64(bps))
	q, _ := bits.Div64(hi, lo, 10_000)
	return q
}

func (m *Memory) RecordPayment(_ context.Context, addr string, p core.Payment, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byAddr[addr]
	if !ok {
		return false, ErrNotFound
	}
	if p.Amount == 0 {
		return false, nil
	}
	key := fmt.Sprintf("payment:%s:%d", strings.ToLower(p.TxHash), p.LogIndex)
	if _, dup := m.book.Get(key); dup {
		return false, nil
	}
	in := m.intents[id]
	bps := in.FeeBps
	if bps > 10_000 {
		bps = 10_000
	}
	fee := feeOf(p.Amount, bps)
	lines := []ledger.Line{
		{Account: ledger.DepositAccount(id), Debit: p.Amount},
		{Account: ledger.MerchantAccount(in.MerchantID, id), Credit: p.Amount - fee},
	}
	if fee > 0 {
		lines = append(lines, ledger.Line{Account: ledger.RevenueFees, Credit: fee})
	}
	if lines[1].Credit == 0 {
		lines = append(lines[:1], lines[2:]...)
	}
	if _, _, err := m.book.Post(ledger.Entry{
		Key: key, Kind: "payment", At: now, Lines: lines,
		Meta: map[string]string{"intent": id, "merchant": in.MerchantID, "tx": strings.ToLower(p.TxHash), "from": p.From, "block": fmt.Sprint(p.BlockNumber)},
	}); err != nil {
		return false, fmt.Errorf("posting payment to ledger: %w", err)
	}

	p.IntentID = id
	m.payments[id] = append(m.payments[id], p)
	if typ := in.ApplyPayment(p.Amount, now); typ != "" {
		ev := core.NewEvent(typ, in, &p, now)
		m.enqueue(ev, now)
		m.enqueueEmailsLocked(ev, in, &p, nil, now)
	}
	m.ensureJobLocked(in, now)
	return true, nil
}

func (m *Memory) ensureJobLocked(in *core.Intent, now time.Time) {
	if jid, ok := m.activeJob[in.ID]; ok {
		j := m.jobs[jid]
		switch j.State {
		case core.SweepQueued:
			j.NextRun = now
			j.Version++
		case core.SweepSigned, core.SweepSubmitted:
			if !j.Resweep {
				j.Resweep = true
				j.Version++
			}
		}
		return
	}
	j := &core.SweepJob{
		ID: core.NewID("swp"), IntentID: in.ID, MerchantID: in.MerchantID, DepositAddress: in.DepositAddress,
		State: core.SweepQueued, NextRun: now, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}
	m.jobs[j.ID] = j
	m.activeJob[in.ID] = j.ID
}

func (m *Memory) ExpireDue(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, in := range m.intents {
		if in.ExpireIfDue(now) {
			m.enqueue(core.NewEvent(core.EventExpired, in, nil, now), now)
			n++
		}
	}
	return n, nil
}

func (m *Memory) LeaseDeliveries(_ context.Context, now time.Time, limit int, lease time.Duration) ([]core.Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var due []*core.Delivery
	for _, d := range m.deliveries {
		if d.DeliveredAt == nil && !d.Dead && !d.NextAttempt.After(now) {
			due = append(due, d)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if !due[i].NextAttempt.Equal(due[j].NextAttempt) {
			return due[i].NextAttempt.Before(due[j].NextAttempt)
		}
		return due[i].Event.ID < due[j].Event.ID
	})
	if len(due) > limit {
		due = due[:limit]
	}
	out := make([]core.Delivery, 0, len(due))
	for _, d := range due {
		out = append(out, *d)
		d.NextAttempt = now.Add(lease)
	}
	return out, nil
}

func (m *Memory) CompleteDelivery(_ context.Context, eventID string, res DeliveryResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.deliveries[eventID]
	if !ok {
		return ErrNotFound
	}
	d.Attempts++
	switch {
	case res.Delivered:
		t := res.At
		d.DeliveredAt = &t
		d.LastError = ""
	case res.Dead:
		d.Dead, d.LastError = true, res.Err
	default:
		d.NextAttempt, d.LastError = res.NextAttempt, res.Err
	}
	return nil
}

func (m *Memory) ListDeliveries(_ context.Context, merchantID string, limit int) ([]core.Delivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []core.Delivery
	for _, d := range m.deliveries {
		if d.Event.MerchantID == merchantID {
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Event.CreatedAt.Equal(out[j].Event.CreatedAt) {
			return out[i].Event.CreatedAt.After(out[j].Event.CreatedAt)
		}
		return out[i].Event.ID > out[j].Event.ID
	})
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) LeaseEmails(_ context.Context, now time.Time, limit int, lease time.Duration) ([]core.Email, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var due []*core.Email
	for _, e := range m.emails {
		if e.SentAt == nil && !e.Dead && !e.NextAttempt.After(now) {
			due = append(due, e)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if !due[i].NextAttempt.Equal(due[j].NextAttempt) {
			return due[i].NextAttempt.Before(due[j].NextAttempt)
		}
		return due[i].ID < due[j].ID
	})
	if len(due) > limit {
		due = due[:limit]
	}
	out := make([]core.Email, 0, len(due))
	for _, e := range due {
		out = append(out, *e)
		e.NextAttempt = now.Add(lease)
	}
	return out, nil
}

func (m *Memory) CompleteEmail(_ context.Context, id string, res EmailResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var target *core.Email
	for _, e := range m.emails {
		if e.ID == id {
			target = e
			break
		}
	}
	if target == nil {
		return ErrNotFound
	}
	target.Attempts++
	switch {
	case res.Sent:
		t := res.At
		target.SentAt = &t
		target.LastError = ""
	case res.Dead:
		target.Dead, target.LastError = true, res.Err
	default:
		target.NextAttempt, target.LastError = res.NextAttempt, res.Err
	}
	return nil
}

func (m *Memory) ListEmails(_ context.Context, merchantID string, limit int) ([]core.Email, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []core.Email
	for _, e := range m.emails {
		if e.MerchantID == merchantID {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) Cursor(context.Context) (uint64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursor, m.cursorSet, nil
}

func (m *Memory) SetCursor(_ context.Context, block uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cursor, m.cursorSet = block, true
	return nil
}

func (m *Memory) LeaseSweepJobs(_ context.Context, now time.Time, limit int, lease time.Duration) ([]core.SweepJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var due []*core.SweepJob
	for _, j := range m.jobs {
		if j.State.Active() && !j.NextRun.After(now) && !j.LeaseUntil.After(now) {
			due = append(due, j)
		}
	}
	sort.Slice(due, func(i, k int) bool {
		if !due[i].NextRun.Equal(due[k].NextRun) {
			return due[i].NextRun.Before(due[k].NextRun)
		}
		return due[i].ID < due[k].ID
	})
	if len(due) > limit {
		due = due[:limit]
	}
	out := make([]core.SweepJob, 0, len(due))
	for _, j := range due {
		j.LeaseUntil = now.Add(lease)
		j.Version++
		out = append(out, *j)
	}
	return out, nil
}

func (m *Memory) SaveSweepJob(_ context.Context, job core.SweepJob, now time.Time) (core.SweepJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.jobs[job.ID]
	if !ok {
		return core.SweepJob{}, ErrNotFound
	}
	if cur.Version != job.Version {
		return core.SweepJob{}, ErrConflict
	}
	if cur.State == core.SweepConfirmed || job.State == core.SweepConfirmed {
		return core.SweepJob{}, fmt.Errorf("%w: confirmation goes through CompleteSweep", ErrInvalid)
	}
	wasFailed := cur.State == core.SweepFailed
	job.Resweep = job.Resweep || cur.Resweep
	job.IntentID, job.MerchantID, job.DepositAddress, job.CreatedAt = cur.IntentID, cur.MerchantID, cur.DepositAddress, cur.CreatedAt
	job.UpdatedAt = now.UTC()
	job.Version = cur.Version + 1
	*cur = job
	if cur.State == core.SweepFailed && !wasFailed {
		if in := m.intents[cur.IntentID]; in != nil {
			m.enqueue(core.NewPayoutEvent(core.EventPayoutFailed, in, cur, now), now)
		}
	}
	return *cur, nil
}

func (m *Memory) CompleteSweep(_ context.Context, jobID string, res SweepResult, now time.Time) (core.SweepJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[jobID]
	if !ok {
		return core.SweepJob{}, ErrNotFound
	}
	if j.State == core.SweepConfirmed {
		return *j, nil
	}
	if j.State != core.SweepSubmitted && j.State != core.SweepSigned {
		return core.SweepJob{}, fmt.Errorf("%w: job is %s", ErrInvalid, j.State)
	}
	if !strings.EqualFold(res.TxHash, j.TxHash) || res.FeeNative == nil {
		return core.SweepJob{}, fmt.Errorf("%w: receipt does not match the signed transaction", ErrInvalid)
	}
	if j.ValueMicro+j.ChargeMicro != j.OwedMicro {
		return core.SweepJob{}, fmt.Errorf("%w: job amounts are inconsistent", ErrInvalid)
	}
	feeMicro, ok := core.CeilNativeToMicro(res.FeeNative)
	if !ok || feeMicro > j.ChargeMicro {
		return core.SweepJob{}, fmt.Errorf("%w: network fee %s exceeds the reserved %s", ErrInvalid, res.FeeNative, core.FormatUSDC(j.ChargeMicro))
	}
	margin := j.ChargeMicro - feeMicro
	lines := []ledger.Line{
		{Account: ledger.MerchantAccount(j.MerchantID, j.IntentID), Debit: j.OwedMicro},
		{Account: ledger.DepositAccount(j.IntentID), Credit: j.ValueMicro + feeMicro},
	}
	if margin > 0 {
		lines = append(lines, ledger.Line{Account: ledger.RevenueNetworkMargin, Credit: margin})
	}
	if _, _, err := m.book.Post(ledger.Entry{
		Key: "sweep:" + jobID, Kind: "sweep", At: now, Lines: lines,
		Meta: map[string]string{"intent": j.IntentID, "merchant": j.MerchantID, "tx": strings.ToLower(j.TxHash), "destination": j.Destination,
			"value_micro": fmt.Sprint(j.ValueMicro), "network_fee_micro": fmt.Sprint(feeMicro), "reserve_micro": fmt.Sprint(j.ChargeMicro)},
	}); err != nil {
		return core.SweepJob{}, fmt.Errorf("posting sweep to ledger: %w", err)
	}

	t := now.UTC()
	j.State, j.ConfirmedAt = core.SweepConfirmed, &t
	j.BlockNumber, j.GasUsed, j.FeeNative, j.FeeMicro, j.MarginMicro = res.BlockNumber, res.GasUsed, res.FeeNative.String(), feeMicro, margin
	j.LeaseUntil, j.UpdatedAt, j.Reason, j.LastError = time.Time{}, t, "", ""
	j.Version++
	delete(m.activeJob, j.IntentID)

	if in := m.intents[j.IntentID]; in != nil {
		ev := core.NewPayoutEvent(core.EventPayoutDone, in, j, now)
		m.enqueue(ev, now)
		m.enqueueEmailsLocked(ev, in, nil, j, now)
		if j.Resweep {
			m.ensureJobLocked(in, now)
		}
	}
	return *j, nil
}

func (m *Memory) RequeueSweepJob(_ context.Context, jobID string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[jobID]
	if !ok {
		return ErrNotFound
	}
	if j.State != core.SweepFailed {
		return fmt.Errorf("%w: only failed jobs can be requeued", ErrInvalid)
	}
	*j = core.SweepJob{
		ID: j.ID, IntentID: j.IntentID, MerchantID: j.MerchantID, DepositAddress: j.DepositAddress,
		State: core.SweepQueued, Version: j.Version + 1, NextRun: now, CreatedAt: j.CreatedAt, UpdatedAt: now.UTC(),
	}
	return nil
}

func (m *Memory) GetSweepJob(_ context.Context, id string) (core.SweepJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return core.SweepJob{}, ErrNotFound
	}
	return *j, nil
}

func (m *Memory) ListSweepJobs(_ context.Context, merchantID string, limit int) ([]core.SweepJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []core.SweepJob
	for _, j := range m.jobs {
		if merchantID == "" || j.MerchantID == merchantID {
			out = append(out, *j)
		}
	}
	sort.Slice(out, func(i, k int) bool {
		if !out[i].CreatedAt.Equal(out[k].CreatedAt) {
			return out[i].CreatedAt.After(out[k].CreatedAt)
		}
		return out[i].ID > out[k].ID
	})
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) OwedMicro(_ context.Context, merchantID, intentID string) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.intents[intentID]
	if !ok || in.MerchantID != merchantID {
		return 0, ErrNotFound
	}
	return m.book.Balance(ledger.MerchantAccount(merchantID, intentID)), nil
}

func (m *Memory) Deposits(_ context.Context) ([]Deposit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Deposit, 0, len(m.intents))
	for id, in := range m.intents {
		busy := false
		if jid, ok := m.activeJob[id]; ok {
			s := m.jobs[jid].State
			busy = s == core.SweepSigned || s == core.SweepSubmitted
		}
		out = append(out, Deposit{IntentID: id, MerchantID: in.MerchantID, Address: in.DepositAddress,
			LedgerMicro: m.book.Balance(ledger.DepositAccount(id)), Busy: busy})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IntentID < out[j].IntentID })
	return out, nil
}

func (m *Memory) MerchantStats(_ context.Context, merchantID string) (Stats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.merchants[merchantID]; !ok {
		return Stats{}, ErrNotFound
	}
	var s Stats
	for _, in := range m.intents {
		if in.MerchantID != merchantID {
			continue
		}
		s.Intents++
		switch in.Status {
		case core.StatusPending:
			s.Pending++
		case core.StatusPaid:
			s.Paid++
		case core.StatusExpired:
			s.Expired++
		}
		for _, p := range m.payments[in.ID] {
			s.VolumeMicro += p.Amount
			bps := in.FeeBps
			if bps > 10_000 {
				bps = 10_000
			}
			s.FeesMicro += feeOf(p.Amount, bps)
		}
	}
	s.PendingPayoutMicro = m.book.BalancePrefix(ledger.MerchantPrefix(merchantID))
	for _, j := range m.jobs {
		if j.MerchantID != merchantID {
			continue
		}
		switch {
		case j.State == core.SweepConfirmed:
			s.PayoutsConfirmed++
			s.SettledMicro += j.ValueMicro
			s.NetworkFeesMicro += j.ChargeMicro
		case j.State == core.SweepFailed:
			s.PayoutsFailed++
		case j.State.Active():
			s.PayoutsInFlight++
		}
	}
	return s, nil
}
