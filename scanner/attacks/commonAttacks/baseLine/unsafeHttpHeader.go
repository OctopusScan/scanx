package baseLine

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/result"
	"time"
)

var checkHeader = []string{
	"X-Frame-Options",
	"X-XSS-Protection",
}

type unsafeHttpHeader struct {
}

func (u *unsafeHttpHeader) check(target base.BaseTarget) (bool, []result.VulMessage) {
	resp, err := target.SendRequest("", base.Param{}, base.DefaultRequestOptionsWithRetry)
	if err != nil {
		return false, nil
	}
	var vulRes []result.VulMessage
	headers := resp.Header
	for _, v := range checkHeader {
		data := headers.Get(v)
		switch v {
		case "X-Frame-Options":
			if data == "" {
				vulRes = append(vulRes, result.VulMessage{
					DataType: result.WebVul,
					VulnData: result.VulnData{
						CreateTime:      time.Now().Format("2006-01-02 15:04:05"),
						VulnType:        result.BaseLines,
						VulnSubType:     result.UnSafeHttpHeader,
						Target:          target.Url,
						Ip:              "",
						Method:          target.Method,
						Param:           "",
						Payload:         "",
						CURLCommand:     "",
						Description:     "The target is not enabled X-Frame-Options header",
						Request:         "",
						Response:        "",
						DirScanExitType: "",
					},
					Plugin: result.BaseLine,
					Level:  result.Low,
				})
			}
		case "X-XSS-Protection":
			if data == "" {
				vulRes = append(vulRes, result.VulMessage{
					DataType: result.WebVul,
					VulnData: result.VulnData{
						CreateTime:      time.Now().Format("2006-01-02 15:04:05"),
						VulnType:        result.BaseLines,
						VulnSubType:     result.UnSafeHttpHeader,
						Target:          target.Url,
						Ip:              "",
						Method:          target.Method,
						Param:           "",
						Payload:         "",
						CURLCommand:     "",
						Description:     "The target is not enabled X-XSS-Protection header",
						Request:         "",
						Response:        "",
						DirScanExitType: "",
					},
					Plugin: result.BaseLine,
					Level:  result.Low,
				})
			}
			if data != "0" && data != "1; mode=block" && data != "" {
				vulRes = append(vulRes, result.VulMessage{
					DataType: result.WebVul,
					VulnData: result.VulnData{
						CreateTime:      time.Now().Format("2006-01-02 15:04:05"),
						VulnType:        result.BaseLines,
						VulnSubType:     result.UnSafeHttpHeader,
						Target:          target.Url,
						Ip:              "",
						Method:          target.Method,
						Param:           "",
						Payload:         "",
						CURLCommand:     "",
						Description:     "The target X-XSS-Protection header have unsafe value",
						Request:         "",
						Response:        "",
						DirScanExitType: "",
					},
					Plugin: result.BaseLine,
					Level:  result.Low,
				})
			}
		case "Strict-Transport-Security":
			if data == "" {
				vulRes = append(vulRes, result.VulMessage{
					DataType: result.WebVul,
					VulnData: result.VulnData{
						CreateTime:      time.Now().Format("2006-01-02 15:04:05"),
						VulnType:        result.BaseLines,
						VulnSubType:     result.UnSafeHttpHeader,
						Target:          target.Url,
						Ip:              "",
						Method:          target.Method,
						Param:           "",
						Payload:         "",
						CURLCommand:     "",
						Description:     "The target is not enabled Strict-Transport-Security header",
						Request:         "",
						Response:        "",
						DirScanExitType: "",
					},
					Plugin: result.BaseLine,
					Level:  result.Low,
				})
			}
		}
	}
	return true, vulRes
}

func newUnsafeHttpHeader() *unsafeHttpHeader {
	return &unsafeHttpHeader{}
}
