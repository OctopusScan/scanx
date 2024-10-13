package base

import (
	"bytes"
	"fmt"
	"github.com/B9O2/Inspector/useful"
	"github.com/Kumengda/httpProxyPool/httpProxyPool"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/corpix/uarand"
	"github.com/zyylhn/httpc"
	"go.uber.org/ratelimit"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/textproto"
	"strings"
)

type ContentType string
type HttpMethod string
type Extension string

const (
	ApplicationJson       ContentType = "application/json"
	ApplicationUrlencoded ContentType = "application/x-www-form-urlencoded"
	MultipartData         ContentType = "multipart/form-data"
	Unknown               ContentType = "unknown"
	GET                   HttpMethod  = "GET"
	POST                  HttpMethod  = "POST"
	PUT                   HttpMethod  = "PUT"
	DELETE                HttpMethod  = "DELETE"
	PhpExtension          Extension   = "php"
	JspExtension          Extension   = "jsp"
)

type Mime struct {
	IsFile     bool
	Data       string
	MimeHeader textproto.MIMEHeader
}

type Response struct {
	RawResponse  *http.Response
	Status       string
	StatusCode   int
	Body         string
	RequestDump  string
	ResponseDump string
	Header       http.Header
	//ContentLength    int
	RequestUrl string
	//Location         string  // todo Location 在httpc里如何获取
	ServerDurationMs float64 // 响应时间
}

type RequestSingleUseOption struct {
	Url     string
	Method  HttpMethod
	Headers map[string]interface{}
}

type RequestOptions struct {
	Redirect    bool
	Retry       bool
	RetryMaxNum int
	RequestSingleUseOption
}

type Session struct {
	ProxyPool   *httpProxyPool.HttpProxyPool
	Client      *httpc.Client
	RateLimiter ratelimit.Limiter // 速率限制，每秒
}

// DefaultResolvers contains the default list of resolvers known to be good
var DefaultResolvers = []string{
	"1.1.1.1",         // Cloudflare
	"1.0.0.1",         // Cloudlfare secondary
	"8.8.8.8",         // Google
	"8.8.4.4",         // Google secondary
	"223.5.5.5",       // AliDNS
	"223.6.6.6",       // AliDNS
	"119.29.29.29",    // DNSPod
	"114.114.114.114", // 114DNS
	"114.114.115.115", // 114DNS
}

var DefaultRequestOptionsWithRetry = RequestOptions{
	Redirect:    false,
	Retry:       true,
	RetryMaxNum: 3,
}

var DefaultRequestOptionsWithoutRetry = RequestOptions{
	Redirect:    false,
	Retry:       false,
	RetryMaxNum: 3,
}

var retryFlag = []string{
	"timeout",
}

func httpcRequest(target string, method HttpMethod, reqData string, isdirect bool, headers map[string]interface{}, session *Session) (*Response, error) {
	if isdirect {
		jar, _ := cookiejar.New(nil)
		session.Client.SetCookieJar(jar)
	}
	req := session.Client.R()
	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "close")
	for k, v := range headers {
		req.Header.Set(k, v.(string))
	}
	switch method {
	case GET:
		target = target + reqData
	case POST:
		req.Body = reqData
	default:

	}
	resp, err := req.Execute(string(method), target)
	if err != nil {
		return ErrResponse, err
	}

	requstRaw, err := resp.Request.GetRaw()
	if err != nil {
		return nil, err
	}
	respRaw, err := resp.GetRaw()
	if err != nil {
		return nil, err
	}
	return &Response{
		RawResponse:  resp.RawResponse,
		Status:       resp.Status(),
		StatusCode:   resp.StatusCode(),
		Body:         string(resp.Body()),
		RequestDump:  string(requstRaw),
		ResponseDump: string(respRaw),
		Header:       resp.GetHeaders(),
		//ContentLength:    int(),
		RequestUrl: resp.Request.URL,
		//Location:         ,
		ServerDurationMs: float64(resp.ReceivedAt().Nanosecond() / 1e6),
	}, nil
}
func proxyPoolRequest(target string, method HttpMethod, reqData string, isdirect bool, headers map[string]interface{}, session *Session) (*Response, error) {
	var req *http.Request
	switch method {
	case GET:
		req, _ = http.NewRequest("GET", target, nil)
	case POST:
		req, _ = http.NewRequest("POST", target, bytes.NewBufferString(reqData))
	default:
		return ErrResponse, nil
	}
	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "close")
	for k, v := range headers {
		req.Header.Set(k, v.(string))

	}
	resp, err := session.ProxyPool.Do(req)
	if err != nil {
		return ErrResponse, err
	}
	var respBody []byte
	defer resp.Body.Close()
	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		return ErrResponse, err
	}
	requstDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return ErrResponse, err
	}
	responseDump, err := httputil.DumpResponse(resp, true)
	return &Response{
		RawResponse:  resp,
		Status:       resp.Status,
		StatusCode:   resp.StatusCode,
		Body:         string(respBody),
		RequestDump:  string(requstDump),
		ResponseDump: string(responseDump),
		Header:       resp.Header,
		//ContentLength:    int(),
		RequestUrl: resp.Request.URL.String(),
		//Location:         ,
		ServerDurationMs: -1,
	}, nil
}
func request(target string, method HttpMethod, reqData string, isdirect bool, headers map[string]interface{}, session *Session) (*Response, error) {
	if session.ProxyPool == nil {
		return httpcRequest(target, method, reqData, isdirect, headers, session)
	} else {
		return proxyPoolRequest(target, method, reqData, isdirect, headers, session)
	}
}

func httpcRequestWithMultiPart(target string, method HttpMethod, headers map[string]interface{}, mimes []Mime, session *Session) (*Response, error) {
	req := session.Client.R()
	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "close")
	for k, v := range headers {
		req.Header.Set(k, v.(string))

	}
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	if mimes != nil {
		for _, m := range mimes {
			part, _ := writer.CreatePart(m.MimeHeader)
			_, _ = io.Copy(part, strings.NewReader(m.Data))
		}
	}
	//fmt.Println(body)
	writer.Close()
	req.Body = io.NopCloser(body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := req.Execute(string(method), target)
	if err != nil {
		return ErrResponse, err
	}

	requstRaw, err := resp.Request.GetRaw()
	if err != nil {
		return nil, err
	}
	respRaw, err := resp.GetRaw()
	if err != nil {
		return nil, err
	}
	return &Response{
		RawResponse:  resp.RawResponse,
		Status:       resp.Status(),
		StatusCode:   resp.StatusCode(),
		Body:         string(resp.Body()),
		RequestDump:  string(requstRaw),
		ResponseDump: string(respRaw),
		Header:       resp.Request.Header,
		//ContentLength:    int(),
		RequestUrl: resp.Request.URL,
		//Location:         ,
		ServerDurationMs: float64(resp.ReceivedAt().Nanosecond() / 1e6),
	}, nil
}
func proxyPoolRequestWithMultiPart(target string, method HttpMethod, headers map[string]interface{}, mimes []Mime, session *Session) (*Response, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	if mimes != nil {
		for _, m := range mimes {
			part, _ := writer.CreatePart(m.MimeHeader)
			_, _ = io.Copy(part, strings.NewReader(m.Data))
		}
	}
	//fmt.Println(body)
	var req *http.Request
	req.Header.Set("Content-Type", writer.FormDataContentType())
	writer.Close()
	switch method {
	case GET:
		req, _ = http.NewRequest("GET", target, io.NopCloser(body))
	case POST:
		req, _ = http.NewRequest("POST", target, io.NopCloser(body))
	default:
		return ErrResponse, nil
	}
	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Connection", "close")
	for k, v := range headers {
		req.Header.Set(k, v.(string))
	}
	resp, err := session.ProxyPool.Do(req)
	if err != nil {
		return ErrResponse, err
	}
	var respBody []byte
	defer resp.Body.Close()
	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		return ErrResponse, err
	}
	requstDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return ErrResponse, err
	}
	responseDump, err := httputil.DumpResponse(resp, true)
	return &Response{
		RawResponse:  resp,
		Status:       resp.Status,
		StatusCode:   resp.StatusCode,
		Body:         string(respBody),
		RequestDump:  string(requstDump),
		ResponseDump: string(responseDump),
		Header:       resp.Header,
		//ContentLength:    int(),
		RequestUrl: resp.Request.URL.String(),
		//Location:         ,
		ServerDurationMs: -1,
	}, nil
}

func requestWithMultiPart(target string, method HttpMethod, headers map[string]interface{}, mimes []Mime, session *Session) (*Response, error) {
	if session.ProxyPool == nil {
		return httpcRequestWithMultiPart(target, method, headers, mimes, session)
	} else {
		return proxyPoolRequestWithMultiPart(target, method, headers, mimes, session)
	}
}

func RequestWithMultipart(target string, method HttpMethod, headers map[string]interface{}, mimes []Mime, session *Session) (*Response, error) {
	maxRetry := 3
	nowRetry := 0
	for {
		resp, err := requestWithMultiPart(target, method, headers, mimes, session)
		nowRetry++
		if err != nil {
			errmsg := strings.ToLower(err.Error())
			retryFlagCheck := false
			for _, v := range retryFlag {
				if strings.Contains(errmsg, v) {
					retryFlagCheck = true
					break
				}
			}
			if !retryFlagCheck {
				return resp, err
			}
		} else {
			return resp, err
		}
		if nowRetry > maxRetry {
			return resp, err
		}
		MainInsp.Print(useful.WARN, useful.Text(fmt.Sprintf("重试条件触发,正在重试%s请求......", target)))

	}
}

// isSupportedProtocol checks given protocols are supported
func isSupportedProtocol(value string) bool {
	return value == "http" || value == "https" || value == "socks5"
}

var ErrResponse = &Response{
	Status:       "ERR",
	StatusCode:   999,
	Body:         "",
	RequestDump:  "",
	ResponseDump: "",
	Header:       nil,
	//ContentLength:    0,
	RequestUrl: "",
	//Location:         "",
	ServerDurationMs: -1,
}
