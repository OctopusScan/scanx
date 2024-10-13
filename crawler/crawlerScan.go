package crawler

import (
	"context"
	"fmt"
	inspect "github.com/B9O2/Inspector"
	"github.com/B9O2/Inspector/useful"
	"github.com/B9O2/Multitasking"
	"github.com/Kumengda/httpProxyPool/httpProxyPool"
	"github.com/OctopusScan/urlCrawlerEngine/crawler"
	"github.com/OctopusScan/urlCrawlerEngine/myClient"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/mySignal"
	"github.com/OctopusScan/webVulScanEngine/result"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/OctopusScan/webVulScanEngine/scanner"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/commonAttacks"
	"github.com/OctopusScan/webVulScanEngine/utils"
	"net/textproto"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type Crawler struct {
	proxyPool           *httpProxyPool.HttpProxyPool
	enableChromeCrawler bool
	targets             []string
	timeout             int
	waitTime            int
	printLog            bool
	depth               int
	crawlerThreads      int
	chromeThreads       int
	scannerConfig       conf.Config
	scanThreads         int
	headless            bool
	headers             map[string]interface{}
	filter              []string
	sigChan             chan os.Signal
}

func NewCrawlerForScan(targets []string, timeout int, depth int, waitTime int, crawlerThreads int, headless bool, chromeThreads int, scanThreads int, headers map[string]interface{}, noCrawlerFilter []string, scannerConfig conf.Config, httpProxyPool *httpProxyPool.HttpProxyPool) *Crawler {
	if headers == nil {
		headers = make(map[string]interface{})
	}
	return &Crawler{
		targets:        targets,
		timeout:        timeout,
		waitTime:       waitTime,
		depth:          depth,
		chromeThreads:  chromeThreads,
		crawlerThreads: crawlerThreads,
		scanThreads:    scanThreads,
		headers:        headers,
		scannerConfig:  scannerConfig,
		headless:       headless,
		filter:         noCrawlerFilter,
		sigChan:        make(chan os.Signal, 1),
		proxyPool:      httpProxyPool,
	}
}
func NewBaseTargetForScan(target string, scanThreads int, headers map[string]interface{}, scannerConfig conf.Config) *Crawler {
	if headers == nil {
		headers = make(map[string]interface{})
	}
	return &Crawler{
		targets:        []string{target},
		scanThreads:    scanThreads,
		crawlerThreads: 5,
		headers:        headers,
		scannerConfig:  scannerConfig,
	}
}

func (c *Crawler) EnableChromeCrawler() {
	c.enableChromeCrawler = true
}

func (c *Crawler) getBaseTarget(target string, ctx context.Context) []base.BaseTarget {
	var headers = make(map[string]string)
	for k, v := range c.headers {
		headers[k] = v.(string)
	}
	nativeClientOptions := myClient.NewNativeOptions(
		headers,
		c.scannerConfig.WebScan.Proxy,
		2,
		time.Duration(c.timeout)*time.Second,
		c.scannerConfig.WebScan.Timeout,
		c.scannerConfig.Ratelimit,
		3,
		1024*1024,
	)
	crawlerOptions := crawler.NewCrawlerOptions(
		inspect.NewInspector("insp", 999),
		2,
		[]string{".*logout.*"},
		1000,
		nativeClientOptions,
		10,
		false,
		2)
	myCrawler, err := crawler.NewCrawler(
		target,
		crawlerOptions,
	)

	if c.enableChromeCrawler {
		chromeCrawler, err := myCrawler.NewChromeCrawler(time.Duration(c.waitTime)*time.Second, c.headless, c.chromeThreads)
		if err != nil {
			return nil
		}
		myCrawler.SetCrawler(chromeCrawler)
	} else {
		nativeCrawler, err := myCrawler.NewNativeCrawler(c.crawlerThreads, c.proxyPool)
		if err != nil {
			return nil
		}
		myCrawler.SetCrawler(nativeCrawler)
	}

	if err != nil {
		return nil
	}
	res := myCrawler.ParamCrawl(ctx)

	var scanBaseTarget []base.BaseTarget
	for _, v := range res {
		var url string
		var requestBody string
		var contentType base.ContentType
		switch v.Method {
		case "GET":
			var pathParam string
			for _, v1 := range v.Param {
				pathParam = pathParam + v1.Name + "=" + v1.Value + "&"
			}
			if pathParam != "" {
				url = v.Url + "?" + pathParam
			} else {
				url = v.Url
			}
			url = strings.TrimSuffix(url, "&")
			contentType = base.ApplicationUrlencoded
		case "POST":
			//如果该表单涉及上传,进入文件上传检测项
			if v.IsFileUpload {
				var mimes []base.Mime
				for _, vv := range v.Param {

					if vv.Type == "file" {
						mimes = append(mimes, base.Mime{
							IsFile:     true,
							Data:       "",
							MimeHeader: textproto.MIMEHeader{"Content-Type": {"{CONTENT_TYPE}"}, "Content-Disposition": {fmt.Sprintf(`form-data; name="%s"; filename="{FILENAME}"`, vv.Name)}},
						})
					} else {
						mimes = append(mimes, base.Mime{
							IsFile:     false,
							Data:       vv.Value,
							MimeHeader: textproto.MIMEHeader{"Content-Disposition": {fmt.Sprintf(`form-data; name="%s"`, vv.Name)}},
						})
					}
				}
				//	如果是一个文件上传类型的表单
				//v.Param[0].Enctype这个地方 如果该表单是文件上传表单,证明一定有参数,v.Param这个数组就是这个表单所有的参数,他们的Enctype都是一样的,Enctype是form表单中的属性。
				//由于v.Param不可能为空,所以取index 0 的Enctype是安全的
				uploadTarget := base.BaseTarget{
					IsDirect:    false,
					Method:      base.POST,
					Url:         v.Url,
					Headers:     c.headers,
					ContentType: base.ContentType(v.Param[0].Enctype),
					Mimes:       mimes,
				}
				scanBaseTarget = append(scanBaseTarget, uploadTarget)
				continue
			}
			for _, v1 := range v.Param {
				requestBody = requestBody + v1.Name + "=" + v1.Value + "&"
			}
			requestBody = strings.TrimSuffix(requestBody, "&")
			url = v.Url
			contentType = base.ContentType(v.Param[0].Enctype)
		}
		MainInsp.Print(useful.INFO, useful.Text(fmt.Sprintf("爬取到目标:%s 是否表单:%t 请求体:%s", url, v.IsForm, requestBody)))
		scanBaseTarget = append(scanBaseTarget, base.BaseTarget{
			IsDirect:    false,
			Method:      base.HttpMethod(v.Method),
			Url:         url,
			RequestBody: requestBody,
			Headers:     utils.CopyMap(c.headers),
			ContentType: contentType,
		})
	}
	return scanBaseTarget
}

func (c *Crawler) Down() {
	c.sigChan <- mySignal.NewAppDownSignal()
}
func (c *Crawler) Scan(attackTypes ...attacks.AttackType) []result.VulMessage {
	scanMt := Multitasking.NewMultitasking("scanMt", nil)
	crawlerMt := Multitasking.NewMultitasking("crawlerMt", scanMt)
	baseLineLoad := false
	dirScanLoad := false
	go func() {
		signal.Notify(c.sigChan, os.Interrupt, syscall.SIGTERM)
		sig := <-c.sigChan
		switch sig {
		case os.Interrupt:
			MainInsp.Print(useful.WARN, useful.Text("程序正在尝试停止,请等待......"))
			crawlerMt.Terminate()
			scanMt.Terminate()
		case mySignal.AppDownSignal{}:
			return
		}
	}()
	crawlerMt.SetController(NewCrawlerMTEC())
	scanMt.SetErrorCallback(func(controller Multitasking.Controller, err error) {
		if err != nil {
			utils.WriteErrorLog(fmt.Sprintf("scanMTError1:%s\n", err.Error()))
		}
	})
	crawlerMt.SetErrorCallback(func(controller Multitasking.Controller, err error) {
		if err != nil {
			utils.WriteErrorLog(fmt.Sprintf("crawlerMTError:%s\n", err.Error()))
		}
	})
	scanMt.Register(func(dc Multitasking.DistributeController) {
		crawlerMt.Run(context.Background(), uint(c.crawlerThreads))
	}, func(ec Multitasking.ExecuteController, i interface{}) interface{} {
		task := i.(base.BaseTarget)
		MainInsp.Print(useful.INFO, useful.Text(fmt.Sprintf("接收到爬虫数据,开始扫描 url:%s", task.Url)))
		scan, err := scanner.NewScanner(c.scannerConfig, task)
		if err != nil {
			return err
		}
		for _, v := range attackTypes {
			if v.GetAttackType() == commonAttacks.Dir || v.GetAttackType() == commonAttacks.BaseLine {
				var isTarget bool
				for _, u := range c.targets {
					if task.Url == strings.TrimSuffix(u, "/") {
						isTarget = true
						break
					}
				}
				if isTarget {
					if v.GetAttackType() == commonAttacks.Dir && !dirScanLoad {
						dirScanLoad = true
						err = scan.LoadAttacks(v)
						if err != nil {
							return err
						}
					}
					if v.GetAttackType() == commonAttacks.BaseLine && !baseLineLoad {
						baseLineLoad = true
						err = scan.LoadAttacks(v)
						if err != nil {
							return err
						}
					}
				}
				continue
			}
			err = scan.LoadAttacks(v)
			if err != nil {
				return err
			}
		}
		return scan.Scan()
	})
	crawlerMt.Register(func(dc Multitasking.DistributeController) {
		for _, v := range c.targets {
			MainInsp.Print(useful.INFO, useful.Text("爬虫任务添加:"+v))
			dc.AddTask(v)
		}
	}, func(ec Multitasking.ExecuteController, i interface{}) interface{} {

		crawlerMTEC := ec.(*CrawlerMTEC)
		target := i.(string)
		//添加目录扫描任务
		rootUrl := strings.TrimSuffix(target, "/")
		crawlerMTEC.InheritDC().AddTask(base.BaseTarget{
			Method:  base.GET,
			Url:     rootUrl,
			Headers: c.headers,
		})
		//添加其他扫描任务
		for _, v := range c.getBaseTarget(target, ec.Context()) {
			if crawlerMTEC.CheckTargetRepeat(v) {
				continue
			}
			crawlerMTEC.AddTarget(v)
			//MainInsp.Print(Text("任务下发:"+v.Url, decorators.Red))
			crawlerMTEC.InheritDC().AddTask(deepCopyBaseTargetHeaders(v))
		}
		return nil
	})
	var finalRes []result.VulMessage
	runRes, _ := scanMt.Run(context.Background(), uint(c.scanThreads))
	for _, v := range runRes {
		switch v.(type) {
		case []result.VulMessage:
			finalRes = append(finalRes, v.([]result.VulMessage)...)
		case error:
			MainInsp.Print(useful.ERROR, useful.Text(fmt.Sprintf("Scan Error %s", v)))
		}
	}
	return finalRes
}

func (c *Crawler) ScanWithCrawlerRes(baseTargets []base.BaseTarget, attackTypes ...attacks.AttackType) []result.VulMessage {
	scanMt := Multitasking.NewMultitasking("scanMt", nil)
	crawlerMt := Multitasking.NewMultitasking("crawlerMt", scanMt)
	baseLineLoad := false
	dirScanLoad := false
	crawlerMt.SetController(NewCrawlerMTEC())
	scanMt.SetErrorCallback(func(controller Multitasking.Controller, err error) {
		if err != nil {
			utils.WriteErrorLog(fmt.Sprintf("scanMTError:2%s\n", err.Error()))
			//buf := make([]byte, 10240)
			//stackSize := runtime.Stack(buf, false)
			//stackTrace := string(buf[:stackSize])
			//log.Printf("Recovered from panic: %v\nStack trace: %s", err, stackTrace)
		}
	})
	crawlerMt.SetErrorCallback(func(controller Multitasking.Controller, err error) {
		if err != nil {
			utils.WriteErrorLog(fmt.Sprintf("crawlerMTError:%s\n", err.Error()))
		}
	})
	scanMt.Register(func(dc Multitasking.DistributeController) {
		crawlerMt.Run(context.Background(), uint(c.crawlerThreads))
	}, func(ec Multitasking.ExecuteController, i interface{}) interface{} {
		task := i.(base.BaseTarget)
		MainInsp.Print(useful.INFO, useful.Text(fmt.Sprintf("接收到爬虫数据,开始扫描 url:%s", task.Url)))
		scan, err := scanner.NewScanner(c.scannerConfig, task)
		if err != nil {
			return err
		}
		for _, v := range attackTypes {
			if v.GetAttackType() == commonAttacks.Dir || v.GetAttackType() == commonAttacks.BaseLine {
				var isTarget bool
				for _, u := range c.targets {
					if task.Url == strings.TrimSuffix(u, "/") {
						isTarget = true
						break
					}
				}
				if isTarget {
					if v.GetAttackType() == commonAttacks.Dir && !dirScanLoad {
						dirScanLoad = true
						err = scan.LoadAttacks(v)
						if err != nil {
							return err
						}
					}
					if v.GetAttackType() == commonAttacks.BaseLine && !baseLineLoad {
						baseLineLoad = true
						err = scan.LoadAttacks(v)
						if err != nil {
							return err
						}
					}
				}
				continue
			}
			err = scan.LoadAttacks(v)
			if err != nil {
				return err
			}
		}
		return scan.Scan()
	})
	crawlerMt.Register(func(dc Multitasking.DistributeController) {
		for _, v := range c.targets {
			MainInsp.Print(useful.INFO, useful.Text("爬虫任务添加:"+v))
			dc.AddTask(v)
		}
	}, func(ec Multitasking.ExecuteController, i interface{}) interface{} {

		crawlerMTEC := ec.(*CrawlerMTEC)
		target := i.(string)
		//添加目录扫描任务
		rootUrl := strings.TrimSuffix(target, "/")
		crawlerMTEC.InheritDC().AddTask(base.BaseTarget{
			Method:  base.GET,
			Url:     rootUrl,
			Headers: c.headers,
		})
		//添加其他扫描任务
		for _, v := range baseTargets {
			if crawlerMTEC.CheckTargetRepeat(v) {
				continue
			}
			crawlerMTEC.AddTarget(v)
			crawlerMTEC.InheritDC().AddTask(deepCopyBaseTargetHeaders(v))
		}
		return nil
	})
	var finalRes []result.VulMessage
	runRes, _ := scanMt.Run(context.Background(), uint(c.scanThreads))
	for _, v := range runRes {
		switch v.(type) {
		case []result.VulMessage:
			finalRes = append(finalRes, v.([]result.VulMessage)...)
		case error:
			MainInsp.Print(useful.ERROR, useful.Text(fmt.Sprintf("Scan Error %s", v)))
		}
	}
	return finalRes
}

func deepCopyBaseTargetHeaders(target base.BaseTarget) base.BaseTarget {
	target.Headers = utils.CopyMap(target.Headers)
	return target
}
