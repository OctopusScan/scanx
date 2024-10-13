package main

import (
	"fmt"
	"github.com/B9O2/Inspector/useful"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/OctopusScan/webVulScanEngine/scanner"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks"
	"time"
)

func main() {
	Init(true)
	//baseTargetFromUser := base.BaseTarget{
	//	IsDirect: false,
	//	Method:   base.POST,
	//	Url:      "https://www.baidu.com",
	//	//Url: "http://192.168.1.14:81/dolbox/code_exec/exec.php?command=&submit=submit",
	//	//Url: "http://127.0.0.1:81/exec.php"
	//
	//	Headers:     map[string]interface{}{},
	//	ContentType: base.MultipartData,
	//	Mimes: []base.Mime{
	//		{
	//			IsFile:     true,
	//			Data:       "",
	//			MimeHeader: textproto.MIMEHeader{"Content-Type": {"{CONTENT_TYPE}"}, "Content-Disposition": {`form-data; name="uploadfile"; filename="{FILENAME}"`}},
	//		},
	//		{
	//			Data:       "开始上传",
	//			MimeHeader: textproto.MIMEHeader{"Content-Disposition": {`form-data; name="submit"`}},
	//		},
	//	},
	//}
	//	Url: "http://127.0.0.1:81/upload/Pass-01/index.php",
	//Url: "http://localhost:81/dolbox/xss/reflect_xss.php?name=1&submit=submit",
	//Url: "http://127.0.0.1:10001/basicxss/vulnerable.php?q=1",
	//Url:         "https://www.baidu.com?a=1",
	//Url: "http://127.0.0.1:9999/Less-1/?id=1",
	//Url:         "http://localhost:81/dolbox/csrf/jsonp.php?callback=test",

	//baseTargetFromBurp, err := utils.LoadBaseTargetFromBurp("D:\\tooooooooooools\\XRAY\\556")

	baseTargetFromUser := base.BaseTarget{
		IsDirect:    false,
		Method:      base.GET,
		Url:         "https://dingsp.bankoftianjin.com:8443/",
		RequestBody: "",
		Headers:     map[string]interface{}{},
		ContentType: base.ApplicationUrlencoded,
	}

	//if err != nil {
	//	return
	//}
	scan, err := scanner.NewScanner(conf.Config{
		WebScan: conf.WebScan{
			Timeout: 20 * time.Second,
			//Proxy:   "http://127.0.0.1:8082",
		},
		Ratelimit: 5000,
	}, baseTargetFromUser)
	if err != nil {
		fmt.Println(err)
		return
	}

	dirScanConfig := conf.DirScanDefaultConfig
	dirScanConfig.Threads = 50
	dbsScanConfig := conf.DbsScanDefaultConfig
	dbsScanConfig.UsingTimeBase = false
	err = scan.LoadAttacks(
		//commonAttacks.BaseLineCheck(),
		//commonAttacks.UploadScan(conf.UploadDefaultConfig),
		//commonAttacks.JsonpScan(),
		//commonAttacks.DirScan(dirScanConfig),
		injectAttacks.CommandInjectScan(conf.CommandInjectDefaultConfig),
		//injectAttacks.DbsScan(dbsScanConfig),
		//injectAttacks.XSScan(conf.XSScanDefaultConfig),
		//injectAttacks.PathTraversalScan(),
		//injectAttacks.XXEScan(),
	)
	if err != nil {
		fmt.Println(err)
		return
	}
	res := scan.Scan()
	for _, v := range res {
		MainInsp.Print(useful.INFO, useful.Json(v))
	}
}
