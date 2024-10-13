package baseLine

import (
	"crypto/tls"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/result"
	"net/http"
	"time"
)

type unsafeTLSSL struct {
}

func (u *unsafeTLSSL) check(target base.BaseTarget) (bool, []result.VulMessage) {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := httpClient.Head(target.Url)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()
	if resp.TLS == nil {
		return true, []result.VulMessage{{
			DataType: result.WebVul,
			VulnData: result.VulnData{
				CreateTime:      time.Now().Format("2006-01-02 15:04:05"),
				VulnType:        result.BaseLines,
				VulnSubType:     result.UnSafeTLSSL,
				Target:          target.Url,
				Ip:              "",
				Method:          target.Method,
				Param:           "",
				Payload:         "",
				CURLCommand:     "",
				Description:     "The target is not enabled for TLS SSL protocol",
				Request:         "",
				Response:        "",
				DirScanExitType: "",
			},
			Plugin: result.BaseLine,
			Level:  result.Medium,
		}}
	}
	if resp.TLS.Version == tls.VersionTLS10 || resp.TLS.Version == tls.VersionTLS11 {
		return true, []result.VulMessage{{
			DataType: result.WebVul,
			VulnData: result.VulnData{
				CreateTime:      time.Now().Format("2006-01-02 15:04:05"),
				VulnType:        result.BaseLines,
				VulnSubType:     result.UnSafeTLSSL,
				Target:          target.Url,
				Ip:              "",
				Method:          target.Method,
				Param:           "",
				Payload:         "",
				CURLCommand:     "",
				Description:     "The SSL protocol version enabled by the target is too low(1.0 or 1.1)",
				Request:         "",
				Response:        "",
				DirScanExitType: "",
			},
			Plugin: result.BaseLine,
			Level:  result.Medium,
		}}
	}
	return false, nil
}

func newUnsafeTLSSL() *unsafeTLSSL {
	return &unsafeTLSSL{}
}
