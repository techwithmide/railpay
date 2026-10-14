package signer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func NewClient(baseURL, token string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

var ErrUnavailable = errors.New("signer unavailable")

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error struct{ Message string } `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Error.Message
		if msg == "" {
			msg = resp.Status
		}
		switch {
		case resp.StatusCode == http.StatusForbidden:
			return &PolicyError{Reason: strings.TrimPrefix(msg, "signer policy: ")}
		case resp.StatusCode >= 500:
			return fmt.Errorf("%w: %s", ErrUnavailable, msg)
		default:
			return fmt.Errorf("signer: %s", msg)
		}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) Address(ctx context.Context, merchantID, intentID string) (string, error) {
	var out struct{ Address string }
	err := c.do(ctx, "POST", "/v1/address", map[string]string{"merchant_id": merchantID, "intent_id": intentID}, &out)
	return out.Address, err
}

func (c *Client) Sign(ctx context.Context, req SignRequest) (*SignResult, error) {
	var out SignResult
	if err := c.do(ctx, "POST", "/v1/sign", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RegisterDestination(ctx context.Context, merchantID, address, requestedBy string) (Destination, error) {
	var out Destination
	err := c.do(ctx, "POST", "/v1/destinations",
		map[string]string{"merchant_id": merchantID, "address": address, "requested_by": requestedBy}, &out)
	return out, err
}

func (c *Client) Destination(ctx context.Context, merchantID string) (Destination, error) {
	var out Destination
	err := c.do(ctx, "GET", "/v1/destinations/"+url.PathEscape(merchantID), nil, &out)
	return out, err
}

var _ Service = (*Client)(nil)
