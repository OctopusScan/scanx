package utils

import (
	"bufio"
	"github.com/B9O2/Inspector/useful"
	"github.com/OctopusScan/webVulScanEngine/base"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/seh-msft/burpxml"
	"net/http"
	"os"
	"strings"
)

func GetStringLines(data string) []string {
	if strings.Index(data, "\r\n") != -1 {
		var res []string
		split := strings.Split(data, "\r\n")
		for _, v := range split {
			res = append(res, v)
		}
		return res
	} else {
		var res []string
		split := strings.Split(data, "\n")
		for _, v := range split {
			res = append(res, v)
		}
		return res
	}
}

func containCT(c base.ContentType, subc base.ContentType) bool {
	return strings.Contains(string(c), string(subc))
}

func parseBody(contentType base.ContentType, r *http.Request) (interface{}, error) {
	handlers := map[base.ContentType]BodyHandler{
		base.ApplicationJson:       applicationJHandler,
		base.ApplicationUrlencoded: applicationUEHandler,
		base.MultipartData:         applicationMDHandler,
	}
	for ct, handler := range handlers {
		if containCT(contentType, ct) {
			return handler(r)
		}
	}
	return applicationDfHandler(r)
}

func LoadBaseTargetFromBurp(filepath string) (base.BaseTarget, error) {
	var baseTarget base.BaseTarget
	var headers = make(map[string]interface{})
	file, err := os.Open(filepath)
	reader := bufio.NewReader(file)
	if err != nil {
		return baseTarget, err
	}

	xmlRes, err := burpxml.Parse(reader, true)
	if err != nil {
		return baseTarget, err
	}
	for _, x := range xmlRes.Items {
		rq, err := http.ReadRequest(bufio.NewReader(strings.NewReader(x.Request.Body)))

		if err != nil {
			return baseTarget, err
		}
		for k, v := range rq.Header {
			headers[k] = strings.Join(v, "")
		}
		baseTarget.Url = x.Url
		baseTarget.Extension = base.Extension(x.Extension)
		baseTarget.Headers = headers
		baseTarget.Method = base.HttpMethod(rq.Method)
		if _, ok := headers["Content-Type"]; ok {
			baseTarget.ContentType = base.ContentType(headers["Content-Type"].(string))
		}
		if baseTarget.Method != base.GET {
			res, err := parseBody(baseTarget.ContentType, rq)
			if err != nil {
				MainInsp.Print(useful.ERROR, FileName("load"), useful.Text("burp文件载入失败"))
				return base.BaseTarget{}, err
			}
			switch res.(type) {
			case []base.Mime:
				var withFileCheck bool
				mimes := res.([]base.Mime)
				for _, m := range mimes {
					if m.IsFile {
						withFileCheck = true
						break
					}
				}
				if withFileCheck {
					baseTarget.Mimes = res.([]base.Mime)
				} else {
					MainInsp.Print(useful.WARN, FileName("load"), useful.Text("multipartData中未检测到文件数据段"))
				}
			case string:
				baseTarget.RequestBody = res.(string)
			default:
				baseTarget.RequestBody = res.(string)
			}
		}
	}
	return baseTarget, err
}
