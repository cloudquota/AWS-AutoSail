package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type ipinfoResp struct {
	IP      string `json:"ip"`
	Org     string `json:"org"`     // 常带 ASN: "AS16509 Amazon.com, Inc."
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
}

func CheckProxyExitIP(ctx context.Context, proxy string) (string, string, error) {
	hc, err := baseHTTPClient(strings.TrimSpace(proxy))
	if err != nil {
		return "", "", err
	}
	hc.Timeout = 12 * time.Second

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://ipinfo.io/json", nil)
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("ipinfo request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("ipinfo http status: %d", resp.StatusCode)
	}

	var j ipinfoResp
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return "", "", fmt.Errorf("ipinfo decode error: %v", err)
	}

	ip := strings.TrimSpace(j.IP)
	asText := strings.TrimSpace(j.Org)

	if ip == "" {
		return "", "", fmt.Errorf("ipinfo returned empty ip")
	}
	if asText == "" {
		asText = "N/A"
	}

	return ip, asText, nil
}
