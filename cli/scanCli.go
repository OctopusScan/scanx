package main

import (
	"fmt"
	"github.com/B9O2/canvas/pixel"
	"github.com/B9O2/tabby"
	"github.com/OctopusScan/webVulScanEngine/app"
	"github.com/tidwall/gjson"
	"strconv"
	"strings"
	"time"
)

var Timeout = tabby.NewTransfer("second", func(s string) (any, error) {
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(i) * time.Second, nil
})

var Targets = tabby.NewTransfer("target", func(s string) (any, error) {
	return strings.Split(s, ","), nil
})

var Headers = tabby.NewTransfer("headers", func(s string) (any, error) {
	var headers = make(map[string]interface{})
	data := gjson.Parse(s)
	for k, v := range data.Map() {
		headers[k] = v.String()
	}
	return headers, nil
})
var RegExp = tabby.NewTransfer("regexp", func(s string) (any, error) {
	var regexp = []string{}
	data := gjson.Parse(s)
	for _, v := range data.Array() {
		regexp = append(regexp, v.String())
	}
	return regexp, nil
})

var Module = tabby.NewTransfer("module", func(s string) (any, error) {
	moduleList := strings.Split(s, ",")
	return moduleList, nil
})

func main() {
	//utils.StartPprofDebug()
	mainApp := app.NewMainApp("v0.2.4", "*表示必要参数")
	mainApp.SetParam("timeout", "超时时间,默认10", tabby.Int(10), "t")
	mainApp.SetParam("rateLimit", "全局速率限制,默认1000/s", tabby.Int(1000), "rl")
	mainApp.SetParam("depth", "爬取深度,默认2", tabby.Int(2), "d")
	mainApp.SetParam("waitTime", "爬虫等待js执行时间,默认5", tabby.Int(5), "wt")
	mainApp.SetParam("crawlerTimeout", "爬虫超时时间,默认60s", tabby.Int(60), "crT")
	mainApp.SetParam("crawlerThreads", "并发同时对多少个目标进行爬取,默认3", tabby.Int(3), "crt")
	mainApp.SetParam("headless", "是否启用无头模式,默认是false", tabby.Bool(false), "hd")
	mainApp.SetParam("chromeThreads", "每一个爬虫任务中的并发数量,默认20", tabby.Int(20), "ct")
	mainApp.SetParam("scanThreads", "同时并发的扫描目标,默认20", tabby.Int(20), "st")
	mainApp.SetParam("dirScanThreads", "目录扫描模块并发数,默认10", tabby.Int(10), "dt")
	mainApp.SetParam("xssScanThreads", "XSS扫描模块并发数,默认5", tabby.Int(5), "xt")
	mainApp.SetParam("usingTimeBase", "是否启用时间盲注,默认false", tabby.Bool(false), "utb")
	mainApp.SetParam("filename", "结果保存的文件名,json格式", tabby.String(""), "fn")
	mainApp.SetParam("targets", "*目标,使用,分割多个扫描目标", Targets(nil), "ts")
	mainApp.SetParam("headers", "请求头,请使用json格式,eg:{\"key\":\"value\"}", Headers(map[string]interface{}{}), "hs")
	mainApp.SetParam("noCrawler", "不进行爬取的url规则,采用正则形式,入参规则eg:[\"regexp1\",\"regexp2\"]", RegExp([]string{}), "nc")
	mainApp.SetParam("proxy", "代理地址", tabby.String(""), "p")
	mainApp.SetParam("simpleRes", "是否启用简单结果模式,默认false", tabby.Bool(false), "sp")
	mainApp.SetParam("enableChrome", "是否启用chrome爬虫", tabby.Bool(false), "ec")

	mainApp.SetParam("module", "启用模块,多个模块采用,分割,不填表示启用所有模块,有如下模块:SQL,XSS,DirScan,JsonpScan,CommandInjection,FileUploadDetect,PathTraversalDetect,XXEDetect,BaseLineDetect",
		Module([]string{}),
		"m")

	t := tabby.NewTabby("scanX", mainApp)
	tc, err := t.Run(nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	if tc == nil {
		return
	}
	err = tc.Display(pixel.Space)
	if err != nil {
		fmt.Println(err)
		return
	}
}
