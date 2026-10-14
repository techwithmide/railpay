package chain

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	payer = "0x1111111111111111111111111111111111111111"
	dep   = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
)

func rpcServer(t *testing.T, handlers map[string]func(params []json.RawMessage) (any, *RPCError)) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		h, ok := handlers[req.Method]
		resp := map[string]any{"jsonrpc": "2.0", "id": 1}
		if !ok {
			resp["error"] = map[string]any{"code": -32601, "message": "method not found"}
		} else if res, rerr := h(req.Params); rerr != nil {
			resp["error"] = map[string]any{"code": rerr.Code, "message": rerr.Message}
		} else {
			resp["result"] = res
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return &Client{URL: srv.URL}
}

func TestTransferLogsAndParse(t *testing.T) {
	c := rpcServer(t, map[string]func([]json.RawMessage) (any, *RPCError){
		"eth_blockNumber": func([]json.RawMessage) (any, *RPCError) { return "0x64", nil },
		"eth_getLogs": func(p []json.RawMessage) (any, *RPCError) {
			var f struct {
				FromBlock, ToBlock, Address string
				Topics                      []any
			}
			_ = json.Unmarshal(p[0], &f)
			recips, _ := f.Topics[2].([]any)
			if f.Address != SystemEmitter || f.Topics[0] != TransferTopic || f.Topics[1] != nil ||
				len(recips) != 1 || recips[0] != addrTopic(dep) || f.FromBlock != "0x5" || f.ToBlock != "0xa" {
				t.Errorf("unexpected filter: %+v", f)
			}
			return []Log{{Address: SystemEmitter, Topics: []string{TransferTopic, addrTopic(payer), addrTopic(dep)},
				Data: "0x" + strings.Repeat("0", 47) + "15af1d78b58c40000", BlockNumber: "0x7", TransactionHash: "0xAB", LogIndex: "0x2"}}, nil
		},
	})
	head, err := c.BlockNumber(context.Background())
	if err != nil || head != 100 {
		t.Fatalf("head=%d err=%v", head, err)
	}
	logs, err := c.TransferLogs(context.Background(), SystemEmitter, 5, 10, []string{dep})
	if err != nil || len(logs) != 1 {
		t.Fatalf("logs=%v err=%v", logs, err)
	}
	tr, err := ParseTransfer(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	if tr.From != payer || tr.To != dep || tr.Amount.String() != "25000000000000000000" || tr.Block != 7 || tr.LogIndex != 2 || tr.TxHash != "0xab" {
		t.Fatalf("bad transfer: %+v", tr)
	}
}

func TestParseTransferRejects(t *testing.T) {
	if _, err := ParseTransfer(Log{Topics: []string{TransferTopic}}); err == nil {
		t.Error("ERC-721-style or malformed log should be rejected")
	}
}

func TestReadMethods(t *testing.T) {
	c := rpcServer(t, map[string]func([]json.RawMessage) (any, *RPCError){
		"eth_chainId": func([]json.RawMessage) (any, *RPCError) { return "0x4cef52", nil },
		"eth_getBalance": func(p []json.RawMessage) (any, *RPCError) {
			if string(p[0]) != `"`+dep+`"` || string(p[1]) != `"latest"` {
				t.Errorf("getBalance params %s %s", p[0], p[1])
			}
			return "0x15af1d78b58c40000", nil
		},
		"eth_getTransactionCount": func(p []json.RawMessage) (any, *RPCError) {
			if string(p[1]) != `"pending"` {
				t.Errorf("nonce must be the pending count, got %s", p[1])
			}
			return "0x7", nil
		},
		"eth_getBlockByNumber":     func([]json.RawMessage) (any, *RPCError) { return map[string]any{"baseFeePerGas": "0x4a817c800"}, nil },
		"eth_maxPriorityFeePerGas": func([]json.RawMessage) (any, *RPCError) { return "0x3b9aca00", nil },
		"eth_getCode":              func([]json.RawMessage) (any, *RPCError) { return "0x", nil },
		"eth_estimateGas":          func([]json.RawMessage) (any, *RPCError) { return "0x5208", nil },
	})
	ctx := context.Background()
	if id, err := c.ChainID(ctx); err != nil || id.Int64() != 5042002 {
		t.Fatalf("chainID %d %v", id, err)
	}
	if b, err := c.BalanceAt(ctx, dep); err != nil || b.String() != "25000000000000000000" {
		t.Fatalf("balance %v %v", b, err)
	}
	if n, err := c.PendingNonceAt(ctx, dep); err != nil || n != 7 {
		t.Fatalf("nonce %d %v", n, err)
	}
	if f, err := c.BaseFee(ctx); err != nil || f.String() != "20000000000" {
		t.Fatalf("base fee %v %v", f, err)
	}
	if tip, err := c.TipCap(ctx); err != nil || tip.String() != "1000000000" {
		t.Fatalf("tip %v %v", tip, err)
	}
	if code, err := c.CodeAt(ctx, dep); err != nil || len(code) != 0 {
		t.Fatalf("code %x %v", code, err)
	}
	if g, err := c.EstimateGas(ctx, payer, dep, big.NewInt(1)); err != nil || g != 21000 {
		t.Fatalf("gas %d %v", g, err)
	}
}

func TestBaseFeeFallsBackToGasPrice(t *testing.T) {
	c := rpcServer(t, map[string]func([]json.RawMessage) (any, *RPCError){
		"eth_getBlockByNumber": func([]json.RawMessage) (any, *RPCError) { return map[string]any{"number": "0x1"}, nil },
		"eth_gasPrice":         func([]json.RawMessage) (any, *RPCError) { return "0x4a817c800", nil },
	})
	if f, err := c.BaseFee(context.Background()); err != nil || f.String() != "20000000000" {
		t.Fatalf("fallback base fee %v %v", f, err)
	}
}

func TestTipCapUnsupportedIsZero(t *testing.T) {
	c := rpcServer(t, map[string]func([]json.RawMessage) (any, *RPCError){}) // every method: -32601
	if tip, err := c.TipCap(context.Background()); err != nil || tip.Sign() != 0 {
		t.Fatalf("tip %v %v", tip, err)
	}
}

func TestReceiptAndSend(t *testing.T) {
	var sent string
	c := rpcServer(t, map[string]func([]json.RawMessage) (any, *RPCError){
		"eth_sendRawTransaction": func(p []json.RawMessage) (any, *RPCError) {
			_ = json.Unmarshal(p[0], &sent)
			if sent == "0xdead" {
				return nil, &RPCError{Code: -32000, Message: "nonce too low"}
			}
			return "0xhash", nil
		},
		"eth_getTransactionReceipt": func(p []json.RawMessage) (any, *RPCError) {
			if string(p[0]) == `"0xmissing"` {
				return nil, nil
			}
			return map[string]any{"transactionHash": "0xABC", "status": "0x1", "blockNumber": "0x2a", "gasUsed": "0x5208", "effectiveGasPrice": "0x4a817c800"}, nil
		},
	})
	ctx := context.Background()
	if err := c.SendRawTransaction(ctx, []byte{0x02, 0x01}); err != nil || sent != "0x0201" {
		t.Fatalf("send: %v %q", err, sent)
	}
	err := c.SendRawTransaction(ctx, []byte{0xde, 0xad})
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) || !strings.Contains(rpcErr.Message, "nonce too low") {
		t.Fatalf("want RPCError, got %v", err)
	}
	r, err := c.Receipt(ctx, "0xabc")
	if err != nil || r == nil || r.Status != 1 || r.BlockNumber != 42 || r.GasUsed != 21000 || r.EffectiveGasPrice.String() != "20000000000" || r.TxHash != "0xabc" {
		t.Fatalf("receipt %+v %v", r, err)
	}
	if r, err := c.Receipt(ctx, "0xmissing"); err != nil || r != nil {
		t.Fatalf("unmined receipt must be nil,nil: %v %v", r, err)
	}
}
