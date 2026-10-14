package chain

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const TransferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

const SystemEmitter = "0xfffffffffffffffffffffffffffffffffffffffe"

const maxRecipientsPerQuery = 200

type Client struct {
	URL  string
	HTTP *http.Client
}

type RPCError struct {
	Method  string
	Code    int
	Message string
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc %s: %d %s", e.Method, e.Code, e.Message) }

type Log struct {
	Address         string   `json:"address"`
	Topics          []string `json:"topics"`
	Data            string   `json:"data"`
	BlockNumber     string   `json:"blockNumber"`
	TransactionHash string   `json:"transactionHash"`
	LogIndex        string   `json:"logIndex"`
}

type Transfer struct {
	From, To string
	Amount   *big.Int
	TxHash   string
	LogIndex uint64
	Block    uint64
}

type Receipt struct {
	TxHash            string
	Status            uint64
	BlockNumber       uint64
	GasUsed           uint64
	EffectiveGasPrice *big.Int
}

func (c *Client) call(ctx context.Context, method string, params, out any) error {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}

	var resp *http.Response
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		req, rErr := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
		if rErr != nil {
			return rErr
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err = hc.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable {
			resp.Body.Close()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt+1) * time.Second):
				continue
			}
		}
		break
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rpc %s: http %d", method, resp.StatusCode)
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&env); err != nil {
		return fmt.Errorf("rpc %s: decode: %w", method, err)
	}
	if env.Error != nil {
		return &RPCError{Method: method, Code: env.Error.Code, Message: env.Error.Message}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

func (c *Client) BlockNumber(ctx context.Context) (uint64, error) {
	var s string
	if err := c.call(ctx, "eth_blockNumber", []any{}, &s); err != nil {
		return 0, err
	}
	return ParseQuantity(s)
}

func (c *Client) Nonce(ctx context.Context, addr string) (uint64, error) {
	var s string
	if err := c.call(ctx, "eth_getTransactionCount", []any{addr, "pending"}, &s); err != nil {
		return 0, err
	}
	return ParseQuantity(s)
}

func (c *Client) GasPrice(ctx context.Context) (*big.Int, error) {
	var s string
	if err := c.call(ctx, "eth_gasPrice", []any{}, &s); err != nil {
		return nil, err
	}
	s = strings.TrimPrefix(s, "0x")
	b := new(big.Int)
	if s != "" {
		b.SetString(s, 16)
	}
	return b, nil
}

func (c *Client) ChainID(ctx context.Context) (*big.Int, error) {
	var s string
	if err := c.call(ctx, "eth_chainId", []any{}, &s); err != nil {
		return nil, err
	}
	s = strings.TrimPrefix(s, "0x")
	b := new(big.Int)
	if s != "" {
		b.SetString(s, 16)
	}
	return b, nil
}

func (c *Client) BalanceAt(ctx context.Context, addr string) (*big.Int, error) {
	return c.bigResult(ctx, "eth_getBalance", []any{addr, "latest"})
}

func (c *Client) PendingNonceAt(ctx context.Context, addr string) (uint64, error) {
	v, err := c.bigResult(ctx, "eth_getTransactionCount", []any{addr, "pending"})
	if err != nil || !v.IsUint64() {
		return 0, fmt.Errorf("eth_getTransactionCount: %v", err)
	}
	return v.Uint64(), nil
}

func (c *Client) BaseFee(ctx context.Context) (*big.Int, error) {
	var blk struct {
		BaseFee string `json:"baseFeePerGas"`
	}
	if err := c.call(ctx, "eth_getBlockByNumber", []any{"latest", false}, &blk); err == nil && blk.BaseFee != "" {
		if v, err := ParseBigQuantity(blk.BaseFee); err == nil && v.Sign() > 0 {
			return v, nil
		}
	}
	return c.bigResult(ctx, "eth_gasPrice", []any{})
}

func (c *Client) TipCap(ctx context.Context) (*big.Int, error) {
	v, err := c.bigResult(ctx, "eth_maxPriorityFeePerGas", []any{})
	if err != nil {
		var rpcErr *RPCError
		if errors.As(err, &rpcErr) {
			return new(big.Int), nil
		}
		return nil, err
	}
	return v, nil
}

func (c *Client) EstimateGas(ctx context.Context, from, to string, value *big.Int) (uint64, error) {
	v, err := c.bigResult(ctx, "eth_estimateGas", []any{map[string]any{"from": from, "to": to, "value": hexBig(value)}})
	if err != nil || !v.IsUint64() {
		return 0, fmt.Errorf("eth_estimateGas: %v", err)
	}
	return v.Uint64(), nil
}

func (c *Client) CodeAt(ctx context.Context, addr string) ([]byte, error) {
	var s string
	if err := c.call(ctx, "eth_getCode", []any{addr, "latest"}, &s); err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

func (c *Client) SendRawTransaction(ctx context.Context, raw []byte) error {
	return c.call(ctx, "eth_sendRawTransaction", []any{"0x" + hex.EncodeToString(raw)}, nil)
}

func (c *Client) Receipt(ctx context.Context, txHash string) (*Receipt, error) {
	var r *struct {
		TxHash   string `json:"transactionHash"`
		Status   string `json:"status"`
		Block    string `json:"blockNumber"`
		GasUsed  string `json:"gasUsed"`
		GasPrice string `json:"effectiveGasPrice"`
	}
	if err := c.call(ctx, "eth_getTransactionReceipt", []any{txHash}, &r); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, nil
	}
	status, err := ParseQuantity(r.Status)
	if err != nil {
		return nil, fmt.Errorf("receipt status: %w", err)
	}
	blk, err := ParseQuantity(r.Block)
	if err != nil {
		return nil, fmt.Errorf("receipt block: %w", err)
	}
	gas, err := ParseQuantity(r.GasUsed)
	if err != nil {
		return nil, fmt.Errorf("receipt gasUsed: %w", err)
	}
	out := &Receipt{TxHash: strings.ToLower(r.TxHash), Status: status, BlockNumber: blk, GasUsed: gas}
	if r.GasPrice != "" {
		if out.EffectiveGasPrice, err = ParseBigQuantity(r.GasPrice); err != nil {
			return nil, fmt.Errorf("receipt effectiveGasPrice: %w", err)
		}
	}
	return out, nil
}

func (c *Client) TransferLogs(ctx context.Context, token string, from, to uint64, recipients []string) ([]Log, error) {
	var all []Log
	for start := 0; start < len(recipients); start += maxRecipientsPerQuery {
		end := min(start+maxRecipientsPerQuery, len(recipients))
		topics := make([]string, 0, end-start)
		for _, r := range recipients[start:end] {
			topics = append(topics, addrTopic(r))
		}
		filter := map[string]any{
			"fromBlock": hexQty(from),
			"toBlock":   hexQty(to),
			"address":   token,
			"topics":    []any{TransferTopic, nil, topics},
		}
		var logs []Log
		if err := c.call(ctx, "eth_getLogs", []any{filter}, &logs); err != nil {
			return nil, err
		}
		all = append(all, logs...)
	}
	return all, nil
}

func ParseTransfer(l Log) (Transfer, error) {
	if len(l.Topics) != 3 || !strings.EqualFold(l.Topics[0], TransferTopic) {
		return Transfer{}, errors.New("not an ERC20 transfer log")
	}
	from, err1 := topicAddr(l.Topics[1])
	to, err2 := topicAddr(l.Topics[2])
	if err1 != nil || err2 != nil {
		return Transfer{}, errors.New("bad address topic")
	}
	amt := new(big.Int)
	if d := strings.TrimPrefix(l.Data, "0x"); d != "" {
		if _, ok := amt.SetString(d, 16); !ok {
			return Transfer{}, errors.New("bad amount data")
		}
	}
	blk, err := ParseQuantity(l.BlockNumber)
	if err != nil {
		return Transfer{}, err
	}
	idx, err := ParseQuantity(l.LogIndex)
	if err != nil {
		return Transfer{}, err
	}
	return Transfer{From: from, To: to, Amount: amt, TxHash: strings.ToLower(l.TransactionHash), LogIndex: idx, Block: blk}, nil
}

func ParseQuantity(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return 0, errors.New("empty quantity")
	}
	return strconv.ParseUint(s, 16, 64)
}

func ParseBigQuantity(s string) (*big.Int, error) {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return nil, errors.New("empty quantity")
	}
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("bad quantity %q", s)
	}
	return v, nil
}

func hexQty(v uint64) string { return "0x" + strconv.FormatUint(v, 16) }

func hexBig(v *big.Int) string { return "0x" + v.Text(16) }

func (c *Client) bigResult(ctx context.Context, method string, params any) (*big.Int, error) {
	var s string
	if err := c.call(ctx, method, params, &s); err != nil {
		return nil, err
	}
	return ParseBigQuantity(s)
}

func addrTopic(addr string) string {
	return "0x" + strings.Repeat("0", 24) + strings.ToLower(strings.TrimPrefix(addr, "0x"))
}

func topicAddr(topic string) (string, error) {
	if len(topic) != 66 {
		return "", errors.New("bad topic length")
	}
	return "0x" + strings.ToLower(topic[26:]), nil
}
