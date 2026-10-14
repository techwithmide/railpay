package ledger

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func payment(key string, amount uint64) Entry {
	return Entry{Key: key, Kind: "payment", Lines: []Line{
		{Account: DepositAccount("pi_1"), Debit: amount},
		{Account: MerchantAccount("m_1", "pi_1"), Credit: amount},
	}}
}

func TestPostBalancesAndBalances(t *testing.T) {
	b := NewBook()
	e, created, err := b.Post(payment("p1", 25_000_000))
	if err != nil || !created || e.Seq != 1 || e.Hash == "" || e.PrevHash != "" {
		t.Fatalf("post: %+v %v %v", e, created, err)
	}
	if got := b.Balance(DepositAccount("pi_1")); got != 25_000_000 {
		t.Fatalf("asset balance %d", got)
	}
	if got := b.Balance(MerchantAccount("m_1", "pi_1")); got != 25_000_000 {
		t.Fatalf("liability balance %d", got)
	}
	sweep := Entry{Key: "s1", Kind: "sweep", Lines: []Line{
		{Account: MerchantAccount("m_1", "pi_1"), Debit: 25_000_000},
		{Account: DepositAccount("pi_1"), Credit: 24_995_000},
		{Account: RevenueNetworkMargin, Credit: 5_000},
	}}
	e2, _, err := b.Post(sweep)
	if err != nil {
		t.Fatal(err)
	}
	if e2.PrevHash != e.Hash {
		t.Fatal("hash chain not linked")
	}
	if b.Balance(DepositAccount("pi_1")) != 5_000 || b.Balance(MerchantAccount("m_1", "pi_1")) != 0 || b.Balance(RevenueNetworkMargin) != 5_000 {
		t.Fatal("balances after sweep wrong")
	}
	if rep := b.Verify(); !rep.OK() || rep.TotalDebits != rep.TotalCredits || rep.Entries != 2 {
		t.Fatalf("verify: %+v", rep)
	}
}

func TestPostRejectsInvalid(t *testing.T) {
	b := NewBook()
	good := payment("k", 10)
	cases := map[string]func(*Entry){
		"unbalanced":   func(e *Entry) { e.Lines[1].Credit = 9 },
		"one line":     func(e *Entry) { e.Lines = e.Lines[:1] },
		"both sides":   func(e *Entry) { e.Lines[0].Credit = 1 },
		"zero line":    func(e *Entry) { e.Lines[0].Debit = 0 },
		"no key":       func(e *Entry) { e.Key = "" },
		"no kind":      func(e *Entry) { e.Kind = "" },
		"bad account":  func(e *Entry) { e.Lines[0].Account = "nowhere:x" },
		"weird chars":  func(e *Entry) { e.Lines[0].Account = "asset:dep osit" },
		"empty suffix": func(e *Entry) { e.Lines[0].Account = "asset:" },
	}
	for name, mutate := range cases {
		e := good
		e.Lines = append([]Line(nil), good.Lines...)
		mutate(&e)
		if _, _, err := b.Post(e); err == nil {
			t.Errorf("%s: should be rejected", name)
		}
	}
	big := Entry{Key: "o", Kind: "x", Lines: []Line{
		{Account: "asset:a", Debit: ^uint64(0)}, {Account: "asset:b", Debit: 1},
		{Account: "liability:c", Credit: ^uint64(0)}, {Account: "liability:d", Credit: 1},
	}}
	if _, _, err := b.Post(big); err == nil {
		t.Error("overflowing entry must be rejected")
	}
	if len(b.Entries()) != 0 {
		t.Fatal("rejected entries must not be stored")
	}
	if _, _, err := b.Post(Entry{Key: "u", Kind: "x", Lines: []Line{{Account: "asset:a", Debit: 5}, {Account: "liability:b", Credit: 4}}}); !errors.Is(err, ErrUnbalanced) {
		t.Errorf("want ErrUnbalanced, got %v", err)
	}
}

func TestOverdraftRejected(t *testing.T) {
	b := NewBook()
	if _, _, err := b.Post(payment("p", 100)); err != nil {
		t.Fatal(err)
	}
	over := Entry{Key: "s", Kind: "sweep", Lines: []Line{
		{Account: MerchantAccount("m_1", "pi_1"), Debit: 101},
		{Account: DepositAccount("pi_1"), Credit: 101},
	}}
	if _, _, err := b.Post(over); !errors.Is(err, ErrOverdraft) {
		t.Fatalf("want ErrOverdraft, got %v", err)
	}
	if b.Balance(DepositAccount("pi_1")) != 100 || len(b.Entries()) != 1 {
		t.Fatal("failed posting must leave the book untouched")
	}
	if _, _, err := b.Post(Entry{Key: "n", Kind: "x", Lines: []Line{
		{Account: DepositAccount("pi_1"), Debit: 50}, {Account: DepositAccount("pi_1"), Credit: 50},
		{Account: "revenue:fees", Credit: 1}, {Account: "asset:other", Debit: 1},
	}}); err != nil {
		t.Fatalf("net-zero on one account is fine: %v", err)
	}
}

func TestIdempotentKey(t *testing.T) {
	b := NewBook()
	first, created, _ := b.Post(payment("same", 7))
	again, created2, err := b.Post(payment("same", 7))
	if err != nil || !created || created2 || again.Seq != first.Seq || again.Hash != first.Hash {
		t.Fatalf("replay: %+v %v %v", again, created2, err)
	}
	if b.Balance(DepositAccount("pi_1")) != 7 {
		t.Fatal("replay must not double count")
	}
	if _, _, err := b.Post(payment("same", 8)); !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("want ErrKeyConflict, got %v", err)
	}
	rev := payment("same", 7)
	rev.Lines[0], rev.Lines[1] = rev.Lines[1], rev.Lines[0]
	if _, created, err := b.Post(rev); err != nil || created {
		t.Fatalf("reordered replay: %v %v", created, err)
	}
}

func TestBalancePrefixAndGet(t *testing.T) {
	b := NewBook()
	for i, m := range []string{"m_1", "m_1", "m_2"} {
		in := fmt.Sprintf("pi_%d", i)
		if _, _, err := b.Post(Entry{Key: "p" + in, Kind: "payment", Lines: []Line{
			{Account: DepositAccount(in), Debit: 10}, {Account: MerchantAccount(m, in), Credit: 10}}}); err != nil {
			t.Fatal(err)
		}
	}
	if b.BalancePrefix(MerchantPrefix("m_1")) != 20 || b.BalancePrefix(MerchantPrefix("m_2")) != 10 || b.BalancePrefix(MerchantPrefix("m_")) != 0 {
		t.Fatal("prefix balances wrong (m_1 must not match m_10 etc.)")
	}
	if e, ok := b.Get("ppi_2"); !ok || e.Seq != 3 {
		t.Fatalf("Get: %+v %v", e, ok)
	}
	if _, ok := b.Get("nope"); ok {
		t.Fatal("unknown key")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	build := func() *Book {
		b := NewBook()
		for i := 0; i < 3; i++ {
			if _, _, err := b.Post(payment(fmt.Sprintf("p%d", i), 100)); err != nil {
				t.Fatal(err)
			}
		}
		return b
	}
	cases := map[string]struct {
		mutate func(*Book)
		want   string
	}{
		"amount edited":     {func(b *Book) { b.entries[1].Lines[0].Debit = 999; b.entries[1].Lines[1].Credit = 999 }, "hash mismatch"},
		"one side edited":   {func(b *Book) { b.entries[1].Lines[0].Debit++ }, "debits"},
		"entry deleted":     {func(b *Book) { b.entries = append(b.entries[:1], b.entries[2:]...) }, "sequence"},
		"chain relinked":    {func(b *Book) { b.entries[2].PrevHash = "00" }, "hash chain broken"},
		"cache out of sync": {func(b *Book) { b.accts[DepositAccount("pi_1")].debits += 5 }, "running balance"},
		"phantom balance":   {func(b *Book) { b.accts["asset:ghost"] = &acct{debits: 1} }, "without entries"},
		"account renamed":   {func(b *Book) { b.entries[0].Lines[0].Account = "asset:deposit:other" }, "hash mismatch"},
	}
	for name, c := range cases {
		b := build()
		if rep := b.Verify(); !rep.OK() {
			t.Fatalf("%s: clean book failed: %v", name, rep.Violations)
		}
		c.mutate(b)
		rep := b.Verify()
		if rep.OK() {
			t.Errorf("%s: tampering not detected", name)
			continue
		}
		if !strings.Contains(strings.Join(rep.Violations, "|"), c.want) {
			t.Errorf("%s: violations %v do not mention %q", name, rep.Violations, c.want)
		}
	}
}

func TestVerifyEntriesZeroSumAndEquation(t *testing.T) {
	e := Entry{Seq: 1, Key: "x", Kind: "x", At: time.Unix(1, 0).UTC(), Lines: []Line{
		{Account: "asset:a", Debit: 10}, {Account: "liability:b", Credit: 9}}}
	e.Hash = entryHash(e)
	rep := VerifyEntries([]Entry{e})
	if rep.OK() {
		t.Fatal("unbalanced entry must fail verification")
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	b := NewBook()
	for i := 0; i < 5; i++ {
		_, _, _ = b.Post(payment(fmt.Sprintf("p%d", i), 10))
	}
	r, err := Restore(b.Entries())
	if err != nil {
		t.Fatal(err)
	}
	if r.Balance(DepositAccount("pi_1")) != 50 || !r.Verify().OK() {
		t.Fatal("restored book differs")
	}
	e, _, err := r.Post(payment("p5", 10))
	if err != nil || e.Seq != 6 || e.PrevHash != b.Entries()[4].Hash {
		t.Fatalf("post after restore: %+v %v", e, err)
	}
	ents := b.Entries()
	ents[2].Lines[0].Debit = 11
	if _, err := Restore(ents); err == nil {
		t.Fatal("restore must refuse tampered entries")
	}
}

func TestHalt(t *testing.T) {
	b := NewBook()
	if h, _ := b.Halted(); h {
		t.Fatal("new book is not halted")
	}
	b.Halt("first")
	b.Halt("second")
	if h, why := b.Halted(); !h || why != "first" {
		t.Fatalf("halted=%v reason=%q (first reason must win)", h, why)
	}
	if _, _, err := b.Post(payment("p", 1)); err != nil {
		t.Fatal(err)
	}
	b.ClearHalt()
	if h, _ := b.Halted(); h {
		t.Fatal("cleared")
	}
}

func TestConcurrentPostsStayZeroSum(t *testing.T) {
	b := NewBook()
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			in := fmt.Sprintf("pi_%d", g)
			for i := 0; i < 50; i++ {
				_, _, err := b.Post(Entry{Key: fmt.Sprintf("p-%d-%d", g, i), Kind: "payment", Lines: []Line{
					{Account: DepositAccount(in), Debit: 3}, {Account: MerchantAccount("m", in), Credit: 3}}})
				if err != nil {
					t.Error(err)
					return
				}
			}
			for i := 0; i < 50; i++ {
				_, _, _ = b.Post(Entry{Key: fmt.Sprintf("p-%d-%d", g, i), Kind: "payment", Lines: []Line{
					{Account: DepositAccount(in), Debit: 3}, {Account: MerchantAccount("m", in), Credit: 3}}})
			}
		}(g)
	}
	wg.Wait()
	rep := b.Verify()
	if !rep.OK() || rep.Entries != 800 || rep.TotalDebits != 2400 || b.BalancePrefix(MerchantPrefix("m")) != 2400 {
		t.Fatalf("report %+v", rep)
	}
}
