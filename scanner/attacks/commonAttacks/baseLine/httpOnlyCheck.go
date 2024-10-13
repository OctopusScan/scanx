package baseLine

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/result"
	"strings"
	"time"
)

type httpOnlyCheck struct {
	checkPoint []string
}

func (h *httpOnlyCheck) check(target base.BaseTarget) (bool, []result.VulMessage) {

	resp, err := target.SendRequest("", base.Param{}, base.DefaultRequestOptionsWithRetry)
	if err != nil {
		return false, nil
	}
	cookies := resp.Header["set-Cookie"]
	for _, c := range cookies {
		for _, ck := range h.checkPoint {
			if strings.Contains(c, ck+"=") {
				if !strings.Contains(c, "HttpOnly") {
					return true, []result.VulMessage{{
						DataType: result.WebVul,
						VulnData: result.VulnData{
							CreateTime:      time.Now().Format("2006-01-02 15:04:05"),
							VulnType:        result.BaseLines,
							VulnSubType:     result.UnSafeCookie,
							Target:          target.Url,
							Ip:              "",
							Method:          target.Method,
							Param:           "",
							Payload:         c,
							CURLCommand:     "",
							Description:     "",
							Request:         resp.RequestDump,
							Response:        resp.ResponseDump,
							DirScanExitType: "",
						},
						Plugin: result.BaseLine,
						Level:  result.Low,
					}}
				}
			}
		}
	}
	return false, nil
}

func newHttpOnlyCheck() *httpOnlyCheck {
	return &httpOnlyCheck{
		checkPoint: []string{"PHPSESSID", "JSESSIONID"},
	}
}
