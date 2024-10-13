package jsonpScan

import (
	"crypto/tls"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/zyylhn/httpc"
	"go.uber.org/ratelimit"
	"net/http"
	"time"
)

func newSession(ratelimiter int) (*base.Session, error) {
	transport := &http.Transport{
		MaxIdleConnsPerHost: -1,
		DisableKeepAlives:   true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}

	_client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(1) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	client := httpc.NewWithClient(_client)
	return &base.Session{
		Client:      client,
		RateLimiter: ratelimit.New(ratelimiter),
	}, nil
}
