package base

import (
	"fmt"
	"github.com/B9O2/Inspector/useful"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"strings"
)

type Os string

var FilterParmas = []string{"submit", "timestamp"}

//var FilterParmas = []string{}

const (
	Windows Os = "Windows"
	Linux   Os = "Linux"
)

type Request struct {
	HttpxSession *Session
}

type BaseTarget struct {
	Request
	Variations  *Variations
	IsDirect    bool
	Method      HttpMethod
	Url         string
	RequestBody string
	Headers     map[string]interface{}
	ContentType ContentType
	Extension   Extension
	Mimes       []Mime
}

func (b *BaseTarget) PrePareVariations(pluginName string) bool {
	variations, _ := ParseUri(b.Url, []byte(b.RequestBody), b.Method, b.ContentType, b.Headers)
	if variations == nil {
		MainInsp.Print(useful.INFO, FileName("commandInject.go"), useful.Text(fmt.Sprintf("[Plugin %s] 总共测试参数共0个", pluginName)))
		return false
	}
	b.Variations = variations
	return true
}
func (b *BaseTarget) GetResponse(param Param, value string) (*Response, error) {
	var err error
	var normalResponse *Response
	normalResponse, err = b.SendRequest(value, param, DefaultRequestOptionsWithRetry)
	if err != nil {
		return nil, err
	}
	return normalResponse, err
}

func (b *BaseTarget) SendRequest(payload string, param Param, options RequestOptions) (*Response, error) {
	if b.Variations == nil {
		b.Variations = &Variations{}
	}
	headers := make(map[string]interface{})
	var reqUrl string
	reqData, url := b.Variations.setPayloadByIndex(param, payload, b.Method, b.Url)
	reqUrl = url
	if options.RequestSingleUseOption.Url != "" {
		reqUrl = options.RequestSingleUseOption.Url
	}
	if options.RequestSingleUseOption.Headers != nil {
		headers = b.Headers
	}
	//fmt.Println(reqData)
	//fmt.Println(reqUrl)
	headers = b.Headers
	maxRetry := options.RetryMaxNum
	nowRetry := 0
	for {
		resp, err := request(reqUrl, b.Method, reqData, options.Redirect, headers, b.Request.HttpxSession)
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
		if !options.Retry {
			return resp, err
		}
		MainInsp.Print(useful.WARN, useful.Text(fmt.Sprintf("重试条件触发,正在重试%s请求......", reqUrl)))
	}
}

func (b *BaseTarget) SendWithMultipart(options RequestOptions, mimes []Mime) (*Response, error) {
	headers := make(map[string]interface{})
	var reqUrl string
	reqUrl = b.Url
	headers = b.Headers
	if options.RequestSingleUseOption.Url != "" {
		reqUrl = options.RequestSingleUseOption.Url
	}
	if options.RequestSingleUseOption.Headers != nil {
		headers = b.Headers
	}

	maxRetry := options.RetryMaxNum
	nowRetry := 0
	for {
		resp, err := requestWithMultiPart(reqUrl, b.Method, headers, mimes, b.Request.HttpxSession)
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
		if !options.Retry {
			return resp, err
		}
		MainInsp.Print(useful.WARN, useful.Text(fmt.Sprintf("重试条件触发,正在重试%s请求......", reqUrl)))
	}
}
