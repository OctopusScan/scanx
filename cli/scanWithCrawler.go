package main

import (
	"encoding/json"
	"fmt"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/crawler"
	"github.com/OctopusScan/webVulScanEngine/result"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks"
	"os"
	"time"
)

func main() {
	//utils.StartPprofDebug()
	//proxyPool := httpProxyPool.NewHttpProxyPool(10)
	//proxyPool.RegistryClientHandler(func(timeout int) []*httpProxyPool.HttpProxyClientInfo {
	//	var httpProxyPools []*httpProxyPool.HttpProxyClientInfo
	//	a, _ := lzProxy.GetProxy("http://192.168.104.151:50001/collect/task/proxy-ip")
	//	for _, v := range a {
	//		info, err := httpProxyPool.NewHttpSockets5ClientInfo(v.Username, v.Password, v.Host, timeout)
	//		if err != nil {
	//			continue
	//		}
	//		httpProxyPools = append(httpProxyPools, &info)
	//	}
	//	return httpProxyPools
	//
	//})
	//proxyPool.SetRetryHandler(func(err error, r *http.Request, response *http.Response) (bool, bool) {
	//	if err != nil {
	//		if strings.Contains(err.Error(), "EOF") {
	//			fmt.Println(err.Error())
	//			return false, true
	//		}
	//		if strings.Contains(err.Error(), "network is down") {
	//			return true, false
	//		}
	//	}
	//	return false, false
	//}, 3)

	base.SimpleRes = true

	err := Init(true)
	if err != nil {
		return
	}
	scanConfig := conf.Config{
		WebScan: conf.WebScan{
			Timeout: 60 * time.Second,
			//Proxy:     "http://127.0.0.1:8080",
			ProxyPool: nil,
		},
		Ratelimit: 5000,
	}

	crawlerScanner := crawler.NewCrawlerForScan(
		[]string{"http://127.0.0.1:8765"},
		60,
		2,
		5,
		20,
		false,
		20,
		2,
		map[string]interface{}{"Cookie": "PHPSESSID=dnkci94tmne1553brkmps8g584; security=low"},
		[]string{".*logout.*"},
		scanConfig,
		nil,
	)
	crawlerScanner.EnableChromeCrawler()

	dirScanConfig := conf.DirScanDefaultConfig
	dirScanConfig.Threads = 10
	xssScanConfig := conf.XSScanDefaultConfig
	xssScanConfig.Threads = 10
	dbsScanConfig := conf.DbsScanDefaultConfig
	dbsScanConfig.UsingTimeBase = false
	commandInjectThreads := conf.CommandInjectDefaultConfig
	commandInjectThreads.ScanThreads = 20
	res := crawlerScanner.Scan(
		//commonAttacks.BaseLineCheck(),
		//commonAttacks.UploadScan(conf.UploadDefaultConfig),
		//commonAttacks.JsonpScan(),
		//commonAttacks.DirScan(dirScanConfig),
		//injectAttacks.CommandInjectScan(commandInjectThreads),
		//injectAttacks.DbsScan(dbsScanConfig),
		injectAttacks.XSScan(conf.XSScanDefaultConfig),
		//injectAttacks.XXEScan(),
		//injectAttacks.PathTraversalScan(),
	)
	var newRes []result.VulMessage
	for _, v := range res {
		fmt.Println(v.VulnData.VulnType)
		v.VulnData.Response = ""
		v.VulnData.Request = ""
		if v.VulnData.VulnType == result.Xss {
			fmt.Println(v.VulnData.Payload)
		}
		if v.VulnData.VulnType != result.DirLeak {
			newRes = append(newRes, v)
		}
	}
	jsonData, _ := json.Marshal(newRes)
	os.WriteFile("result.json", jsonData, 0644)
	crawlerScanner.Down()
}
