package xxeInject

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/result"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks"
	"net/url"
	"strings"
	"time"
)

type pathTraversalPayload struct {
	payload    string
	checkPoint []string
}
type XXEInject struct {
	injectAttacks.BaseInject
	payloads []pathTraversalPayload
}

func (x *XXEInject) StartAttack() ([]result.VulMessage, error) {
	ok := x.PrePareVariations(string(result.XXETraversalDetect))
	if !ok {
		return []result.VulMessage{}, nil
	}
	x.generatePayload()
	for _, param := range x.Variations.Params {
		for _, v := range x.payloads {
			var response *base.Response
			var err error
			xxePayload := strings.ReplaceAll(injectAttacks.XXEInjectReadFile, "{{PATH}}", v.payload)
			response, err = x.SendRequest(xxePayload, param, base.DefaultRequestOptionsWithRetry)
			if err == nil {
				for _, c := range v.checkPoint {
					if strings.Contains(response.Body, c) {
						return []result.VulMessage{
							{
								DataType: result.WebVul,
								VulnData: result.VulnData{
									CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
									VulnType:    result.XXE,
									VulnSubType: result.XXEFileRead,
									Target:      x.Url,
									Method:      x.Method,
									Param:       param.Name,
									Payload:     xxePayload,
									CURLCommand: "",
									Description: "",
									Request:     response.RequestDump,
									Response:    response.ResponseDump,
								},
								Plugin: result.XXETraversalDetect,
								Level:  result.Critical,
							},
						}, nil
					}
				}
			}

		}
	}
	return []result.VulMessage{}, nil
}
func (x *XXEInject) generatePayload() {
	for _, ptf := range base.FileReaderCheckFlags {
		switch ptf.OsType {
		case base.Windows:
			fileSeparator := "/"
			filename := strings.ReplaceAll(ptf.FileName, "{separator}", fileSeparator)
			payload := "file:///C:/" + filename
			x.payloads = append(x.payloads, pathTraversalPayload{
				payload:    payload,
				checkPoint: ptf.CheckPoint,
			})
			x.payloads = append(x.payloads, pathTraversalPayload{
				payload:    url.QueryEscape(payload),
				checkPoint: ptf.CheckPoint,
			})
		case base.Linux:
			fileSeparator := base.OsSeparators[base.Linux]
			filename := strings.ReplaceAll(ptf.FileName, "{separator}", fileSeparator)
			payload := "file://" + fileSeparator + filename
			x.payloads = append(x.payloads, pathTraversalPayload{
				payload:    payload,
				checkPoint: ptf.CheckPoint,
			})
			x.payloads = append(x.payloads, pathTraversalPayload{
				payload:    url.QueryEscape(payload),
				checkPoint: ptf.CheckPoint,
			})
		}
	}
}
func NewXXEInject(target base.BaseTarget) *XXEInject {
	return &XXEInject{
		BaseInject: injectAttacks.BaseInject{BaseTarget: target},
	}
}
