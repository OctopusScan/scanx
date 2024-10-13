package base

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/B9O2/Inspector/useful"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/thoas/go-funk"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strings"
)

type Param struct {
	Name        string      `json:"name"`
	Value       string      `json:"value,omitempty"`
	Filename    string      `json:"filename,omitempty"`
	ContentType ContentType `json:"contentType,omitempty"`

	FileHeader   textproto.MIMEHeader
	FileSize     int64
	FileContent  []byte
	IsFile       bool
	Boundary     string
	FileNotFound bool
	IsBase64     bool
	Index        int
}

type Variations struct {
	MimeType       ContentType `json:"mimeType"`
	Params         []Param     `json:"params"`
	OriginalParams []Param     `json:"originalParams"`
	Text           string      `json:"text"`
}

func (v Variations) Len() int {
	return len(v.Params)
}

func (v Variations) Less(i, j int) bool {
	return v.Params[i].Index < v.Params[j].Index
}

func (v Variations) Swap(i, j int) {
	v.Params[i], v.Params[j] = v.Params[j], v.Params[i]
}

func ParseUri(uri string, body []byte, method HttpMethod, contentType ContentType, headers map[string]interface{}) (*Variations, error) {
	var (
		err        error
		index      int
		variations Variations
	)
	jsonMap := make(map[string]interface{})
	switch method {
	case GET:
		if !funk.Contains(uri, "?") {
			return nil, fmt.Errorf("get request data is empty")
		}
		urlparams := strings.TrimRight(uri, "&")
		urlparams = strings.Split(urlparams, "?")[1]
		strs := strings.Split(urlparams, "&")
		for i, kv := range strs {
			kvs := strings.Split(kv, "=")
			if len(kvs) == 2 {
				key := kvs[0]
				value := kvs[1]
				variations.Params = append(variations.Params, Param{
					Name:        key,
					Value:       value,
					ContentType: contentType,
					Index:       i,
				})
				variations.OriginalParams = append(variations.OriginalParams, Param{
					Name:        key,
					Value:       value,
					ContentType: contentType,
					Index:       i,
				})
			} else {
				continue
			}
		}
		sort.Sort(variations)
		return &variations, nil
	case POST:
		if len(body) < 0 {
			return nil, fmt.Errorf("post request body is empty")
		}
		switch contentType {
		case ApplicationJson:
			err := json.Unmarshal(body, &jsonMap)
			if err != nil {
				return nil, err
			}
			for k, v := range jsonMap {
				if v != nil {
					if value, ok := v.(string); ok {
						Post := Param{
							Name:        k,
							Value:       value,
							ContentType: contentType,
							Index:       index,
						}
						variations.Params = append(variations.Params, Post)
						variations.OriginalParams = append(variations.OriginalParams, Post)
					}
				}
				index++
			}
			variations.MimeType = contentType
		case MultipartData:
			var iindex = 0
			var boundary string
			iobody := bytes.NewReader(body)
			req, err := http.NewRequest(string(method), uri, iobody)
			for k, v := range headers {
				req.Header[k] = []string{v.(string)}
			}
			if err != nil {
				MainInsp.Print(useful.ERROR, FileName("utils.go"), useful.Text(err.Error()))
				return nil, err
			}

			reader, err := req.MultipartReader()
			if err != nil {
				return nil, err
			}
			_, params, err := mime.ParseMediaType(string(contentType))
			if err != nil {
				MainInsp.Print(useful.ERROR, FileName("utils.go"), useful.Text(fmt.Sprintf("mime.ParseMediaType: %v", err)))
			}
			if value, ok := params["boundary"]; ok {
				boundary = value
			}

			for {
				var isfile = false
				if reader == nil {
					break
				}
				p, err := reader.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					MainInsp.Print(useful.ERROR, FileName("utils.go"), useful.Text(fmt.Sprintf("mime.ParseMediaType: %v", err)))
					return nil, err
				}
				body, err := ioutil.ReadAll(p)
				if err != nil {
					p.Close()
					return nil, err
				}
				iindex++
				if p.FileName() != "" {
					isfile = true
				}

				variations.MimeType = contentType
				variations.Params = append(variations.Params, Param{
					Name:        p.FormName(),
					Value:       string(body),
					Filename:    p.FileName(),
					ContentType: ContentType(p.Header.Get("Content-Type")),
					//FileHeader:   nil,
					//FileSize:     0,
					//FileContent:  nil,
					IsFile:   isfile,
					Boundary: boundary,
					//FileNotFound: false,
					//IsBase64:     false,
					Index: iindex,
				})
				variations.OriginalParams = append(variations.OriginalParams, Param{
					Name:        p.FileName(),
					Value:       string(body),
					Filename:    p.FileName(),
					ContentType: ContentType(p.Header.Get("Content-Type")),
					IsFile:      isfile,
					Boundary:    boundary,
					Index:       iindex,
				})
				p.Close()
			}
		default:
			strs := strings.Split(string(body), "&")
			for i, kv := range strs {
				kvs := strings.Split(kv, "=")
				if len(kvs) == 2 {
					key := kvs[0]
					value := kvs[1]
					Post := Param{
						Name:        key,
						Value:       value,
						ContentType: contentType,
						Index:       i,
					}
					variations.Params = append(variations.Params, Post)
					variations.OriginalParams = append(variations.OriginalParams, Post)
				} else {
					//MainInsp.Print(useful.ERROR, FileName("utils.go"), useful.Text("exec function Split err"))
					return nil, err
				}
			}
			variations.MimeType = contentType
		}
		sort.Sort(variations)
		return &variations, nil
	default:
		err = fmt.Errorf("method not support")
	}
	return nil, err
}

func getContentType(data string) ContentType {
	if funk.Contains(data, ApplicationJson) {
		return ApplicationJson
	}
	if funk.Contains(data, ApplicationUrlencoded) {
		return ApplicationUrlencoded
	}
	if funk.Contains(data, MultipartData) {
		return MultipartData
	}
	return Unknown
}

func (p Variations) set(key string, value string) error {
	for i, Param := range p.Params {
		if Param.Name == key {
			p.Params[i].Value = value
			return nil
		}
	}
	return fmt.Errorf("not found: %s", key)
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

func (p *Variations) release() string {
	var buf bytes.Buffer
	mjson := make(map[string]interface{})
	if p.MimeType == "application/json" {
		for _, Param := range p.Params {
			mjson[Param.Name] = Param.Value
		}
		jsonary, err := json.Marshal(mjson)
		if err != nil {
			MainInsp.Print(useful.ERROR, FileName("utils.go"), useful.Text(err.Error()))
		}
		buf.Write(jsonary)
	} else if funk.Contains(p.MimeType, "multipart/form-data") {
		// bodyBuf := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(&buf)
		// bodyWriter.CreateFormFile(p.Params[0], p.Params[0].Filename)

		if p.Params[0].Boundary != "" {
			bodyWriter.SetBoundary(p.Params[0].Boundary)
		}

		for _, Param := range p.Params {
			if Param.IsFile {

				h := make(textproto.MIMEHeader)
				h.Set("Content-Disposition",
					fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
						escapeQuotes(Param.Name), escapeQuotes(Param.Filename)))
				h.Set("Content-Type", string(Param.ContentType))
				part, err := bodyWriter.CreatePart(h)
				if err != nil {
					MainInsp.Print(useful.ERROR, FileName("utils.go"), useful.Text(err.Error()))
				}
				// 写入文件数据到multipart，和读取本地文件方法的唯一区别
				_, err = part.Write([]byte(Param.Value))
			} else {
				_ = bodyWriter.WriteField(Param.Name, Param.Value)
			}
		}
		bodyWriter.Close()
		// fmt.Println(buf.String())
	} else {
		for i, Param := range p.Params {
			buf.WriteString(Param.Name + "=" + Param.Value)
			if i != p.Len()-1 {
				buf.WriteString("&")
			}
		}
	}

	return buf.String()
}

func (p *Variations) setPayloadByIndex(param Param, payload string, method HttpMethod, uri string) (string, string) {
	u, err := url.Parse(uri)
	rawUrl := u.Scheme + "://" + u.Host + u.Path
	if err != nil {
		MainInsp.Print(useful.ERROR, useful.Text(err.Error()))
		return "", rawUrl
	}
	switch param.ContentType {
	case ApplicationJson:
		// json不进行任何url 编码=
	default:
		// 对 payload 进行 url 编码
		payload = url.QueryEscape(payload)
	}
	switch method {
	case GET:
		//v := u.Query()
		for idx, kv := range p.Params {
			if idx == param.Index {
				p.set(kv.Name, payload)
				stv := p.release()
				//str := strings.Split(uri, "?")[0] + "?" + stv
				//v.set(kv.Name, kv.Value)
				p.set(kv.Name, p.OriginalParams[idx].Value)
				p.release()
				return "?" + stv, rawUrl
			}
		}
	case POST:
		for idx, kv := range p.Params {
			if idx == param.Index {
				// 先改变参数，生成 payload，然后再将参数改回来，将现场还原
				p.set(kv.Name, payload)
				str := p.release()
				p.set(kv.Name, p.OriginalParams[idx].Value)
				p.release()
				return str, rawUrl
			}

		}
	}
	return "", rawUrl
}
