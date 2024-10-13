package utils

import (
	"fmt"
	"github.com/B9O2/Inspector/useful"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync"
)

var lock sync.Mutex

func WriteErrorLog(log string) {
	MainInsp.Print(useful.ERROR, useful.Text(log))
	//lock.Lock()
	//var DEBUG_FILE_PATH = "./debug"
	//file, err := os.OpenFile(DEBUG_FILE_PATH, os.O_RDWR|os.O_CREATE, 0666)
	//if err != nil {
	//	MainInsp.Print(useful.ERROR, useful.Text("错误日志文件打开/创建失败:"+err.Error()))
	//	return
	//}
	//defer file.Close()
	//_, err = file.WriteString(log)
	//if err != nil {
	//	MainInsp.Print(useful.ERROR, useful.Text("错误日志写入失败:"+err.Error()))
	//	return
	//}
	//lock.Unlock()
}
func StartPprofDebug() {
	go func() {
		err := http.ListenAndServe(":6060", nil)
		if err != nil {
			fmt.Println("PPROF START FAILED:" + err.Error())
			os.Exit(0)
		}
	}()
}
