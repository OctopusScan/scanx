package xssInject

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/B9O2/Inspector/useful"
	"github.com/B9O2/Multitasking"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/result"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks"
	"github.com/OctopusScan/webVulScanEngine/utils"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/tidwall/gjson"
	"golang.org/x/net/html"
	"strconv"
	"strings"
	"time"
)

//go:embed xss_payload
var xssPayload string

type XssInject struct {
	injectAttacks.BaseInject
	config              conf.XSScanConfig
	payloads            []string
	xssPayloadRandomNum string
}

type transitStruct struct {
	payload string
	resp    string
	param   string
	method  base.HttpMethod
	req     string
}

func NewXssInject(target base.BaseTarget, config conf.XSScanConfig) *XssInject {
	var payloads []string
	payloadRandomNum := utils.RandNumber(10000, 50000)
	tmpPayloads := utils.GetStringLines(xssPayload)
	for _, v := range tmpPayloads {
		payloads = append(payloads, strings.ReplaceAll(v, "{NUM}", strconv.Itoa(payloadRandomNum)))
	}
	return &XssInject{
		config:              config,
		BaseInject:          injectAttacks.BaseInject{BaseTarget: target},
		xssPayloadRandomNum: strconv.Itoa(payloadRandomNum),
		payloads:            payloads,
	}
}

func (x *XssInject) StartAttack() ([]result.VulMessage, error) {
	ok := x.PrePareVariations("XSS")
	if !ok {
		return []result.VulMessage{}, nil
	}
	var vulRes []result.VulMessage
	finalPayloadGroup := groupStrings(x.payloads, 10)
	fatherMt := Multitasking.NewMultitasking("xssScanFather", nil)
	fatherMt.SetErrorCallback(func(controller Multitasking.Controller, err error) {
		if err != nil {
			utils.WriteErrorLog(fmt.Sprintf("fatherMtError:%s\n", err.Error()))
		}
	})
	fatherMt.Register(func(dc Multitasking.DistributeController) {
		for _, v := range finalPayloadGroup {
			dc.AddTask(v)
		}
	}, func(ec Multitasking.ExecuteController, i interface{}) interface{} {
		task := i.([]string)
		//headers := x.Headers
		//fmt.Printf("init:%p\n", &headers)
		sonMt := Multitasking.NewMultitasking("xssScanSon", nil)
		sonMt.SetErrorCallback(func(controller Multitasking.Controller, err error) {
			if err != nil {
				utils.WriteErrorLog(fmt.Sprintf("xssinject:sonMtError:%s\n", err.Error()))
			}
		})
		sonMt.Register(func(sonDc Multitasking.DistributeController) {
			for _, v := range task {
				sonDc.AddTask(v)
			}
		}, func(sonEc Multitasking.ExecuteController, i interface{}) interface{} {
			payload := i.(string)
			for _, v := range x.Variations.Params {
				response, _ := x.SendRequest(v.Value+payload, v, base.DefaultRequestOptionsWithRetry)
				if response != nil {
					body := parseBody(response)
					if strings.Contains(body, x.xssPayloadRandomNum) {
						return transitStruct{
							payload: payload,
							resp:    response.ResponseDump,
							req:     response.RequestDump,
							param:   v.Name,
							method:  x.Method,
						}
					}
					return nil
				}
			}
			return nil
		})
		res, _ := sonMt.Run(context.Background(), uint(x.config.Threads))
		var sonMtRes []transitStruct
		if res != nil {
			for _, v := range res {
				if v != nil {
					sonMtRes = append(sonMtRes, v.(transitStruct))
				}
			}
		}

		successPayload := x.jsSandBox(sonMtRes)

		if len(successPayload) != 0 {
			return successPayload
		}
		return nil
	})
	fatherMt.SetResultMiddlewares(Multitasking.NewBaseMiddleware(func(ec Multitasking.ExecuteController, i interface{}) (interface{}, error) {
		if i != nil {
			ec.Terminate()
		}
		return i, nil
	}))
	res, _ := fatherMt.Run(context.Background(), 5)
	for _, v := range res {
		if v != nil {
			resData := v.([]transitStruct)
			for _, v1 := range resData {
				vulRes = append(vulRes, result.VulMessage{
					DataType: result.WebVul,
					VulnData: result.VulnData{
						CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
						VulnType:    result.Xss,
						VulnSubType: result.ReflectXss,
						Target:      x.Url,
						//ip:          "",
						Method:      v1.method,
						Param:       v1.param,
						Payload:     v1.payload,
						CURLCommand: "",
						Description: "",
						Request:     v1.req,
						Response:    v1.resp,
					},
					Plugin: result.XssInject,
					Level:  result.Medium,
				})
				//MainInsp.Print(useful.DEBUG, Json(v1))
			}

		}
	}
	return vulRes, nil
}

func (x *XssInject) jsSandBox(tran []transitStruct) []transitStruct {
	var successPayload []transitStruct
	var isXss bool
	ctx, _ := context.WithCancel(context.Background())
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("proxy-server", "http://localhost:0"), //禁用网络链接
		chromedp.Flag("headless", true),                     //设置为false以禁用无头模式
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-network", true),
	)
	ctx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	ctx, cancel = chromedp.NewContext(ctx)

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			if ev.(*page.EventJavascriptDialogOpening).Message == x.xssPayloadRandomNum {
				isXss = true
			}
			go func() {
				chromedp.Run(ctx,
					page.HandleJavaScriptDialog(true),
				)
			}()
		}
	})
	for _, v := range tran {
		sbody := splitBody(v.resp, x.xssPayloadRandomNum)
		err := chromedp.Run(ctx, chromedp.Navigate("data:text/html,"+sbody))
		if err != nil {
			MainInsp.Print(useful.DEBUG, FileName("xssInject.go"), useful.Text(err.Error()))
		}
		if isXss {
			successPayload = append(successPayload, v)
			if base.SimpleRes {
				return successPayload
			}
			isXss = false
		}
	}
	cancel()
	return successPayload

}

func splitBody(s string, sub string) string {
	//	doc, err := html.Parse(strings.NewReader(s))
	//	if err != nil {
	//
	//	}
	//	return getXssText(doc, sub)
	idx := strings.LastIndex(s, sub)
	if idx == -1 {
		return ""
	}
	start := idx - 200
	end := idx + len(sub) + 200
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

func parseBody(response *base.Response) (resBody string) {
	defer func() {
		if r := recover(); r != nil {
			resBody = response.Body
		}
	}()
	ct := response.RawResponse.Header.Get("Content-Type")
	if ct == string(base.ApplicationJson) {
		resBody = traverseJSON(response.Body, "")
	} else {
		resBody = response.Body
	}
	return
}
func groupStrings(strings []string, numGroups int) [][]string {
	if numGroups <= 0 {
		return nil
	}

	groupSize := (len(strings) + numGroups - 1) / numGroups
	grouped := make([][]string, 0, numGroups)

	for i := 0; i < len(strings); i += groupSize {
		end := i + groupSize
		if end > len(strings) {
			end = len(strings)
		}
		grouped = append(grouped, strings[i:end])
	}

	return grouped
}
func traverseJSON(json string, totalStr string) string {
	r := gjson.Parse(json)
	r.ForEach(func(key, value gjson.Result) bool {
		if value.IsObject() || value.IsArray() {
			traverseJSON(value.String(), totalStr)
		} else {
			totalStr = totalStr + value.String()
		}
		return true
	})
	return totalStr
}
func getXssText(node *html.Node, search string) string {
	for c := node.FirstChild; c != nil; c = c.NextSibling {
		text := getXssText(c, search)
		if strings.Contains(text, search) {
			var attribute string
			for _, attr := range node.Attr {
				attribute = attribute + fmt.Sprintf("%s=\"%s\" ", attr.Key, attr.Val)
			}
			if node.Data == "" {
				return text
			}
			leftNode := fmt.Sprintf("<%s %s>", node.Data, attribute)
			rightNode := fmt.Sprintf("</%s>", node.Data)
			return leftNode + text + rightNode
		}
	}
	return node.Data
}
