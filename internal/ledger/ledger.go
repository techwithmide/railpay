package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnbalanced  = errors.New("ledger: entry debits do not equal credits")
	ErrInvalid     = errors.New("ledger: invalid entry")
	ErrOverdraft   = errors.New("ledger: posting would overdraw an account")
	ErrKeyConflict = errors.New("ledger: idempotency key resued with different lines")
)

type Kind int

const (
	Asset Kind = iota + 1
	Liability
	Revenue
	Expense
)

func (k Kind) debitNormal() bool { return k == Asset || k == Expense }

func KindOf(account string) (Kind, error) {
	switch {
	case strings.HasPrefix(account, "asset:"):
		return Asset, nil
	case strings.HasPrefix(account, "liability:"):
		return Liability, nil
	case strings.HasPrefix(account, "revenue:"):
		return Revenue, nil
	case strings.HasPrefix(account, "expense:"):
		return Expense, nil
	}
	return 0, fmt.Errorf("%w: unknown account kind %q", ErrInvalid, account)
}

const (
	RevenueFees          = "revenue:fees"
	RevenueNetworkMargin = "revenue:network_margin"
)

func DepositAccount(intentID string) string { return "asset:deposit:" + intentID }

func MerchantAccount(merchantID, intentID string) string {
	return "liability:merchant:" + merchantID + ":" + intentID
}

func MerchantPrefix(merchantID string) string { return "liability:merchant:" + merchantID + ":" }

type Line struct {
	Account string `json:"account"`
	Debit   uint64 `json:"debit"`
	Credit  uint64 `json:"credit"`
}

type Entry struct {
	Seq      uint64            `json:"seq"`
	Key      string            `json:"key"`
	Kind     string            `json:"kind"`
	At       time.Time         `json:"at"`
	Memo     string            `json:"memo,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
	Lines    []Line            `json:"lines"`
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
}

func (e Entry) clone() Entry {
	c := e
	c.Lines = append([]Line(nil), e.Lines...)
	if e.Meta != nil {
		c.Meta = make(map[string]string, len(e.Meta))
		for k, v := range e.Meta {
			c.Meta[k] = v
		}
	}
	return c
}

func validAccount(a string) bool {
	if len(a) < 7 || len(a) > 200 {
		return false
	}
	for _, c := range a {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == ':' || c == '-' || c == '.') {
			return false
		}
	}
	_, err := KindOf(a)
	return err == nil
}

func totals(lines []Line) (debit, credit uint64, err error) {
	var c1, c2 uint64
	for _, l := range lines {
		debit, c1 = bits.Add64(debit, l.Debit, 0)
		credit, c2 = bits.Add64(credit, l.Credit, 0)
		if c1 != 0 || c2 != 0 {
			return 0, 0, fmt.Errorf("%w: amount overflow", ErrInvalid)
		}
	}
	return debit, credit, nil
}

func validate(e Entry) error {
	if e.Key == "" || len(e.Key) > 200 {
		return fmt.Errorf("%w: key must be 1-200 characters", ErrInvalid)
	}
	if e.Kind == "" {
		return fmt.Errorf("%w: kind is required", ErrInvalid)
	}
	if len(e.Lines) < 2 {
		return fmt.Errorf("%w: need at least two lines", ErrInvalid)
	}
	for i, l := range e.Lines {
		if !validAccount(l.Account) {
			return fmt.Errorf("%w: line %d has invalid account %q", ErrInvalid, i, l.Account)
		}
		if (l.Debit == 0) == (l.Credit == 0) {
			return fmt.Errorf("%w: line %d must have exactly one non-zero side", ErrInvalid, i)
		}
	}
	d, c, err := totals(e.Lines)
	if err != nil {
		return err
	}
	if d != c {
		return fmt.Errorf("%w: debits %d, credits %d", ErrUnbalanced, d, c)
	}
	return nil
}

func entryHash(e Entry) string {
	canon := struct {
		Seq   uint64            `json:"seq"`
		Key   string            `json:"key"`
		Kind  string            `json:"kind"`
		At    int64             `json:"at"`
		Memo  string            `json:"memo"`
		Meta  map[string]string `json:"meta"`
		Lines []Line            `json:"lines"`
		Prev  string            `json:"prev"`
	}{e.Seq, e.Key, e.Kind, e.At.UnixNano(), e.Memo, e.Meta, e.Lines, e.PrevHash}
	b, _ := json.Marshal(canon)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func sameLines(a, b []Line) bool {
	if len(a) != len(b) {
		return false
	}
	norm := func(ls []Line) []Line {
		c := append([]Line(nil), ls...)
		sort.Slice(c, func(i, j int) bool {
			if c[i].Account != c[j].Account {
				return c[i].Account < c[j].Account
			}
			if c[i].Debit != c[j].Debit {
				return c[i].Debit < c[j].Debit
			}
			return c[i].Credit < c[j].Credit
		})
		return c
	}
	x, y := norm(a), norm(b)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

type acct struct{ debits, credits uint64 }

func (a acct) net(k Kind) (uint64, bool) {
	if k.debitNormal() {
		if a.debits < a.credits {
			return 0, false
		}
		return a.debits - a.credits, true
	}
	if a.credits < a.debits {
		return 0, false
	}
	return a.credits - a.debits, true
}

type Book struct {
	mu      sync.RWMutex
	entries []Entry
	byKey   map[string]int
	accts   map[string]*acct
	halted  string
	Now     func() time.Time
}

func NewBook() *Book {
	return &Book{byKey: map[string]int{}, accts: map[string]*acct{}, Now: time.Now}
}

func (b *Book) Post(e Entry) (Entry, bool, error) {
	if err := validate(e); err != nil {
		return Entry{}, false, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if i, ok := b.byKey[e.Key]; ok {
		if !sameLines(b.entries[i].Lines, e.Lines) {
			return Entry{}, false, fmt.Errorf("%w: %s", ErrKeyConflict, e.Key)
		}
		return b.entries[i].clone(), false, nil
	}

	staged := map[string]acct{}
	for _, l := range e.Lines {
		a, ok := staged[l.Account]
		if !ok {
			if cur := b.accts[l.Account]; cur != nil {
				a = *cur
			}
		}
		var c1, c2 uint64
		a.debits, c1 = bits.Add64(a.debits, l.Debit, 0)
		a.credits, c2 = bits.Add64(a.credits, l.Credit, 0)
		if c1 != 0 || c2 != 0 {
			return Entry{}, false, fmt.Errorf("%w: account total overflow", ErrInvalid)
		}
		staged[l.Account] = a
	}
	for name, a := range staged {
		k, _ := KindOf(name)
		if _, ok := a.net(k); !ok {
			return Entry{}, false, fmt.Errorf("%w: %s", ErrOverdraft, name)
		}
	}

	e = e.clone()
	e.Seq = uint64(len(b.entries) + 1)
	if e.At.IsZero() {
		e.At = b.Now()
	}
	e.At = e.At.UTC()
	if n := len(b.entries); n > 0 {
		e.PrevHash = b.entries[n-1].Hash
	}
	e.Hash = entryHash(e)
	for name, a := range staged {
		a := a
		b.accts[name] = &a
	}
	b.byKey[e.Key] = len(b.entries)
	b.entries = append(b.entries, e)
	return e.clone(), true, nil
}

func (b *Book) Balance(account string) uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.balanceLocked(account)
}

func (b *Book) balanceLocked(account string) uint64 {
	a := b.accts[account]
	if a == nil {
		return 0
	}
	k, _ := KindOf(account)
	n, _ := a.net(k)
	return n
}

func (b *Book) BalancePrefix(prefix string) uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var sum uint64
	for name := range b.accts {
		if strings.HasPrefix(name, prefix) {
			sum += b.balanceLocked(name)
		}
	}
	return sum
}

func (b *Book) Get(key string) (Entry, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	i, ok := b.byKey[key]
	if !ok {
		return Entry{}, false
	}
	return b.entries[i].clone(), true
}

func (b *Book) Entries() []Entry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Entry, len(b.entries))
	for i, e := range b.entries {
		out[i] = e.clone()
	}
	return out
}

func Restore(entries []Entry) (*Book, error) {
	if rep := VerifyEntries(entries); !rep.OK() {
		return nil, fmt.Errorf("ledger: persisted entries failed verification: %s", strings.Join(rep.Violations, "; "))
	}
	b := NewBook()
	for _, e := range entries {
		b.entries = append(b.entries, e.clone())
		b.byKey[e.Key] = len(b.entries) - 1
		for _, l := range e.Lines {
			a := b.accts[l.Account]
			if a == nil {
				a = &acct{}
				b.accts[l.Account] = a
			}
			a.debits += l.Debit
			a.credits += l.Credit
		}
	}
	return b, nil
}

func (b *Book) Halt(reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.halted == "" {
		b.halted = reason
	}
}

func (b *Book) Halted() (bool, string) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.halted != "", b.halted
}

func (b *Book) ClearHalt() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.halted = ""
}

type Report struct {
	Entries      int      `json:"entries"`
	Accounts     int      `json:"accounts"`
	TotalDebits  uint64   `json:"total_debits"`
	TotalCredits uint64   `json:"total_credits"`
	Violations   []string `json:"violations"`
}

func (r Report) OK() bool { return len(r.Violations) == 0 }

func VerifyEntries(entries []Entry) Report {
	var rep Report
	fail := func(format string, a ...any) { rep.Violations = append(rep.Violations, fmt.Sprintf(format, a...)) }
	accts := map[string]*acct{}
	seen := map[string]bool{}
	prev := ""
	for i, e := range entries {
		rep.Entries++
		if e.Seq != uint64(i+1) {
			fail("entry %d: sequence is %d", i+1, e.Seq)
		}
		if err := validate(e); err != nil {
			fail("entry %d (%s): %v", e.Seq, e.Key, err)
			continue
		}
		if seen[e.Key] {
			fail("entry %d: duplicate key %s", e.Seq, e.Key)
		}
		seen[e.Key] = true
		if e.PrevHash != prev {
			fail("entry %d (%s): hash chain broken", e.Seq, e.Key)
		}
		if h := entryHash(e); h != e.Hash {
			fail("entry %d (%s): hash mismatch (entry was modified)", e.Seq, e.Key)
		}
		prev = e.Hash
		for _, l := range e.Lines {
			a := accts[l.Account]
			if a == nil {
				a = &acct{}
				accts[l.Account] = a
			}
			a.debits += l.Debit
			a.credits += l.Credit
			rep.TotalDebits += l.Debit
			rep.TotalCredits += l.Credit
		}
	}
	rep.Accounts = len(accts)
	if rep.TotalDebits != rep.TotalCredits {
		fail("zero-sum violated: total debits %d != total credits %d", rep.TotalDebits, rep.TotalCredits)
	}
	var debitNormal, creditNormal uint64
	for name, a := range accts {
		k, err := KindOf(name)
		if err != nil {
			continue
		}
		n, ok := a.net(k)
		if !ok {
			fail("account %s is overdrawn (debits %d, credits %d)", name, a.debits, a.credits)
		}
		if k.debitNormal() {
			debitNormal += n
		} else {
			creditNormal += n
		}
	}
	if debitNormal != creditNormal {
		fail("accounting equation violated: debit-normal balances %d != credit-normal balances %d", debitNormal, creditNormal)
	}
	return rep
}

func (b *Book) Verify() Report {
	b.mu.RLock()
	defer b.mu.RUnlock()
	rep := VerifyEntries(b.entries)
	recomputed := map[string]*acct{}
	for _, e := range b.entries {
		for _, l := range e.Lines {
			a := recomputed[l.Account]
			if a == nil {
				a = &acct{}
				recomputed[l.Account] = a
			}
			a.debits += l.Debit
			a.credits += l.Credit
		}
	}
	for name, a := range recomputed {
		if c := b.accts[name]; c == nil || *c != *a {
			rep.Violations = append(rep.Violations, fmt.Sprintf("account %s: running balance disagrees with entries", name))
		}
	}
	for name := range b.accts {
		if recomputed[name] == nil {
			rep.Violations = append(rep.Violations, fmt.Sprintf("account %s: balance exists without entries", name))
		}
	}
	return rep
}
