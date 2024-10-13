package pathTraversal

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/result"
	"net/url"
	"strings"
	"time"
)

type pathTraversalPayload struct {
	payload    string
	checkPoint []string
}

type PathTraversal struct {
	base.BaseTarget
	payloads []pathTraversalPayload
}

func (p *PathTraversal) StartAttack() ([]result.VulMessage, error) {
	ok := p.PrePareVariations(string(result.PathTraversalDetect))
	if !ok {
		return []result.VulMessage{}, nil
	}
	p.generatePayload()

	for _, param := range p.Variations.Params {
		for _, v := range p.payloads {
			var response *base.Response
			var err error
			response, err = p.SendRequest(v.payload, param, base.DefaultRequestOptionsWithRetry)
			if err == nil {
				for _, c := range v.checkPoint {
					if strings.Contains(response.Body, c) {
						return []result.VulMessage{
							{
								DataType: result.WebVul,
								VulnData: result.VulnData{
									CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
									VulnType:    result.PathTraversal,
									VulnSubType: result.ArbitraryFileRead,
									Target:      p.Url,
									Method:      p.Method,
									Param:       param.Name,
									Payload:     v.payload,
									CURLCommand: "",
									Description: "",
									Request:     response.RequestDump,
									Response:    response.ResponseDump,
								},
								Plugin: result.PathTraversalDetect,
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

func (p *PathTraversal) generatePayload() {
	for _, ptf := range base.FileReaderCheckFlags {
		switch ptf.OsType {
		case base.Windows:
			fileSeparator := base.OsSeparators[base.Windows]
			filename := strings.ReplaceAll(ptf.FileName, "{separator}", fileSeparator)
			payload := strings.Repeat(".."+fileSeparator, 10) + filename
			p.payloads = append(p.payloads, pathTraversalPayload{
				payload:    payload,
				checkPoint: ptf.CheckPoint,
			})
			p.payloads = append(p.payloads, pathTraversalPayload{
				payload:    url.QueryEscape(payload),
				checkPoint: ptf.CheckPoint,
			})
		case base.Linux:
			fileSeparator := base.OsSeparators[base.Linux]
			filename := strings.ReplaceAll(ptf.FileName, "{separator}", fileSeparator)
			payload := strings.Repeat(".."+fileSeparator, 10) + filename
			p.payloads = append(p.payloads, pathTraversalPayload{
				payload:    payload,
				checkPoint: ptf.CheckPoint,
			})
			p.payloads = append(p.payloads, pathTraversalPayload{
				payload:    url.QueryEscape(payload),
				checkPoint: ptf.CheckPoint,
			})
		}
	}
}

func NewPathTraversalScanner(target base.BaseTarget) *PathTraversal {
	return &PathTraversal{BaseTarget: target}
}
