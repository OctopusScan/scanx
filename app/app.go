package app

import (
	"encoding/json"
	"github.com/B9O2/canvas/containers"
	"github.com/B9O2/canvas/pixel"
	"github.com/B9O2/tabby"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/crawler"
	"github.com/OctopusScan/webVulScanEngine/result"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/commonAttacks"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks"
	"os"
	"strconv"
	"time"
)

type MainApp struct {
	*tabby.BaseApplication
	version string
	tips    string
}

func NewMainApp(version, tips string) *MainApp {
	return &MainApp{BaseApplication: tabby.NewBaseApplication(0, 0, nil),
		version: version,
		tips:    tips}
}

func (m MainApp) Detail() (string, string) {
	return "scanner", "detail"
}

func (m MainApp) Main(arguments tabby.Arguments) (*tabby.TabbyContainer, error) {
	base.SimpleRes = arguments.Get("simpleRes").(bool)
	if arguments.IsEmpty() {
		m.Help(m.version + "\n" + m.tips)
		return nil, nil
	}
	err := Init(true)
	if err != nil {
		return nil, err
	}
	scanConfig := conf.Config{
		WebScan: conf.WebScan{
			Timeout: time.Duration(arguments.Get("timeout").(int)) * time.Second,
			Proxy:   arguments.Get("proxy").(string),
		}, Ratelimit: arguments.Get("rateLimit").(int),
	}
	crawlerScanner := crawler.NewCrawlerForScan(
		arguments.Get("targets").([]string),
		arguments.Get("crawlerTimeout").(int),
		arguments.Get("depth").(int),
		arguments.Get("waitTime").(int),
		arguments.Get("crawlerThreads").(int),
		arguments.Get("headless").(bool),
		arguments.Get("chromeThreads").(int),
		arguments.Get("scanThreads").(int),
		arguments.Get("headers").(map[string]interface{}),
		arguments.Get("noCrawler").([]string),
		scanConfig,
		nil,
	)
	if arguments.Get("enableChrome").(bool) {
		crawlerScanner.EnableChromeCrawler()
	}

	dirScanConfig := conf.DirScanDefaultConfig
	dirScanConfig.Threads = arguments.Get("dirScanThreads").(int)
	xssScanConfig := conf.XSScanDefaultConfig
	xssScanConfig.Threads = arguments.Get("xssScanThreads").(int)
	dbsScanConfig := conf.DbsScanDefaultConfig
	dbsScanConfig.UsingTimeBase = arguments.Get("usingTimeBase").(bool)
	var enablePlugin []attacks.AttackType
	for _, v := range arguments.Get("module").([]string) {
		switch v {
		case string(result.XssInject):
			enablePlugin = append(enablePlugin, injectAttacks.XSScan(conf.XSScanDefaultConfig))
		case string(result.SqlInject):
			enablePlugin = append(enablePlugin, injectAttacks.DbsScan(dbsScanConfig))
		case string(result.DirScan):
			enablePlugin = append(enablePlugin, commonAttacks.DirScan(dirScanConfig))
		case string(result.JsonpScan):
			enablePlugin = append(enablePlugin, commonAttacks.JsonpScan())
		case string(result.CommandInjection):
			enablePlugin = append(enablePlugin, injectAttacks.CommandInjectScan(conf.CommandInjectDefaultConfig))
		case string(result.FileUploadDetect):
			enablePlugin = append(enablePlugin, commonAttacks.UploadScan(conf.UploadDefaultConfig))
		case string(result.PathTraversalDetect):
			enablePlugin = append(enablePlugin, injectAttacks.PathTraversalScan())
		case string(result.XXETraversalDetect):
			enablePlugin = append(enablePlugin, injectAttacks.XXEScan())
		case string(result.BaseLine):
			enablePlugin = append(enablePlugin, commonAttacks.BaseLineCheck())
		}
	}
	if len(enablePlugin) == 0 {
		enablePlugin = append(enablePlugin,
			injectAttacks.XSScan(conf.XSScanDefaultConfig),
			injectAttacks.DbsScan(dbsScanConfig),
			commonAttacks.DirScan(dirScanConfig),
			commonAttacks.JsonpScan(),
			injectAttacks.CommandInjectScan(conf.CommandInjectDefaultConfig),
			injectAttacks.PathTraversalScan(),
			commonAttacks.UploadScan(conf.UploadDefaultConfig),
			injectAttacks.XXEScan(),
			commonAttacks.BaseLineCheck())
	}
	res := crawlerScanner.Scan(enablePlugin...)
	filename := arguments.Get("filename").(string)
	if filename != "" {
		jsonData, _ := json.Marshal(res)
		os.WriteFile(filename, jsonData, 0644)
	}

	var xssNum int
	var sqlNum int
	var dirNum int
	var jsonpNum int
	var commandNum int
	var fileUploadNum int
	var pathTraversalNum int
	var xxeNum int
	var baseLineNum int

	for _, v := range res {
		switch v.Plugin {
		case result.XssInject:
			xssNum++
		case result.SqlInject:
			sqlNum++
		case result.DirScan:
			dirNum++
		case result.JsonpScan:
			jsonpNum++
		case result.CommandInject:
			commandNum++
		case result.FileUploadDetect:
			fileUploadNum++
		case result.PathTraversalDetect:
			pathTraversalNum++
		case result.XXETraversalDetect:
			xxeNum++
		case result.BaseLine:
			baseLineNum++
		}
	}

	crawlerScanner.Down()

	hs := containers.NewHStack(
		generateVs(xssNum, result.XssInject),
		generateVs(sqlNum, result.SqlInject),
		generateVs(dirNum, result.DirScan),
		generateVs(jsonpNum, result.JsonpScan),
		generateVs(commandNum, result.CommandInject),
		generateVs(fileUploadNum, result.FileUploadDetect),
		generateVs(pathTraversalNum, result.PathTraversalDetect),
		generateVs(xxeNum, result.XXETraversalDetect),
		generateVs(baseLineNum, result.BaseLine),
	)
	hs.SetBorder(pixel.Dot)
	tabbyContainer := tabby.NewTabbyContainer(100, 20, hs)
	return tabbyContainer, nil
}

func generateVs(num int, name result.Plugin) *containers.VStack {
	//if num == 0 {
	//	return nil
	//}
	infoTa := containers.NewTextArea(strconv.Itoa(num))
	infoTa.SetBorder(pixel.Dot)
	nameTa := containers.NewTextArea(string(name))
	nameTa.SetBorder(pixel.Dot)
	vs := containers.NewVStack(nameTa, infoTa)
	vs.SetBorder(pixel.Dot)
	return vs
}
