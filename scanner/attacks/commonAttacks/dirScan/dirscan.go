package dirScan

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/B9O2/Multitasking"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/result"
	"github.com/OctopusScan/webVulScanEngine/utils"
	"regexp"
	"strings"
	"time"
)

//go:embed dict
var dirPaths string

const (
	TIMEOUT int = iota
	UNKNOWN
)

type DirScanner struct {
	base.BaseTarget
	config conf.DirScanConfig
	Paths  map[string][]string
}

func NewDirScanner(target base.BaseTarget, config conf.DirScanConfig) (*DirScanner, error) {
	paths, err := loadPath()
	if err != nil {
		return nil, err
	}
	return &DirScanner{
		BaseTarget: target,
		Paths:      paths,
		config:     config,
	}, nil

}

func (s *DirScanner) StartAttack() ([]result.VulMessage, error) {
	var finalResult []result.VulMessage
	results := s.run()

	for _, v := range results.Paths.Common {
		finalResult = append(finalResult, result.VulMessage{
			DataType: result.WebVul,
			VulnData: result.VulnData{
				CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
				VulnType:    result.DirLeak,
				VulnSubType: result.SensitivePath,
				Target:      s.Url,
				//ip:          "",
				Method:          "GET",
				Param:           "",
				Payload:         v,
				CURLCommand:     "",
				Description:     "",
				Request:         "",
				Response:        "",
				DirScanExitType: string(results.ErrorUpperLimitExitType),
			},
			Plugin: result.DirScan,
			Level:  result.Critical,
		})
	}
	for _, v := range results.Paths.Jsmap {
		finalResult = append(finalResult, result.VulMessage{
			DataType: result.WebVul,
			VulnData: result.VulnData{
				CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
				VulnType:    result.JsMap,
				VulnSubType: result.JsMapLeak,
				Target:      s.Url,
				//ip:          "",
				Method:      "GET",
				Param:       "",
				Payload:     v,
				CURLCommand: "",
				Description: "",
				Request:     "",
				Response:    "",
			},
			Plugin: result.DirScan,
			Level:  result.Critical,
		})
	}
	return finalResult, nil
}
func (s *DirScanner) run() DirScanResults {
	var dirScanResults DirScanResults
	hyperRootCheckEC := NewHyperEC(s.config.DirScanMaxRootCheckRetryLimit)
	hyperMaxRetryCheckEC := NewHyperEC(s.config.DirScanMaxRetryLimit)
	myMT := Multitasking.NewMultitasking("dirScan", nil)
	taskDistributeMt := Multitasking.NewMultitasking("taskDistributeMt", myMT)
	myMT.SetErrorCallback(func(controller Multitasking.Controller, err error) {
		fmt.Println(err)
	})
	taskDistributeMt.SetErrorCallback(func(controller Multitasking.Controller, err error) {
		fmt.Println(err)
	})
	myMT.SetController(hyperMaxRetryCheckEC)
	taskDistributeMt.SetController(hyperRootCheckEC)
	taskDistributeMt.SetErrorCallback(func(controller Multitasking.Controller, err error) {
		if err != nil {
			utils.WriteErrorLog(fmt.Sprintf("taskDistributeMtError:%s\n", err.Error()))
		}
	})
	///任务分发///
	taskDistributeMt.Register(func(tddc Multitasking.DistributeController) {
		//检查root是否可访问
		tddc.AddTask(&dirScanTargetTask{
			IsRandomCheckPath: true,
			ChildPath:         []string{""},
			TargetUrl:         s.Url,
			//Path:              "sajidh21398rh",
			Path: utils.GenerateRandomString(20),
		})
		for root, child := range s.Paths {
			tddc.AddTask(&dirScanTargetTask{
				ChildPath: child,
				TargetUrl: s.Url,
				Path:      root,
			})
		}
	}, func(ec Multitasking.ExecuteController, i interface{}) interface{} {
		hec := ec.(*HyperEC)
		task := i.(*dirScanTargetTask)
		if len(task.ChildPath) == 0 {
			//	说明该条url没有root,直接下发任务
			return []string{task.Path}
		}
		res := s.sendRequest(task)
		if res.IsRandomCheckPath {
			if res.Code == 200 {
				return res
			} else {
				return nil
			}
		}
		//这里是为了检测对特定目录下,任何路由都返回相同响应的情况
		randomCheckTask := dirScanTargetTask{
			TargetUrl: task.TargetUrl,
			Path:      task.Path + "/" + utils.GenerateRandomString(20),
		}
		randomCheckResp := s.sendRequest(&randomCheckTask)
		switch randomCheckResp.Code {
		case TIMEOUT:
			task.IsTimeOut = true
			hec.CheckTerminate(task)
			return hec.Retry(task)
		case 200:
			return randomCheckResp
		}
		switch res.Code {
		case TIMEOUT:
			//fmt.Println("timeout parentCheck retrying....", task.Path)
			task.IsTimeOut = true
			hec.CheckTerminate(task)
			return hec.Retry(task)
		case 403, 406, 401, 200, 301:
			return task.ChildPath
		default:
			//fmt.Println("root不可访问:" + task.Path)
			return res
		}
	})
	rootCheckMiddleWare := newRootCheckMiddleWare(rootCheckMiddlewareFunc, s.Url, s.config)
	taskDistributeMt.SetResultMiddlewares(rootCheckMiddleWare)
	myMT.SetErrorCallback(func(controller Multitasking.Controller, err error) {
		if err != nil {
			utils.WriteErrorLog(fmt.Sprintf("myMtError:%s\n", err.Error()))
		}
	})
	///任务执行///
	myMT.Register(func(dc Multitasking.DistributeController) {
		taskDistributeMt.Run(context.Background(), uint(s.config.Threads))
	}, func(ec Multitasking.ExecuteController, i interface{}) interface{} {
		hec := ec.(*HyperEC)
		task := i.(*dirScanTargetTask)
		res := s.sendRequest(task)
		switch res.Code {
		case TIMEOUT:
			//fmt.Println("timeout retrying....", task.Path)
			task.IsTimeOut = true
			hec.CheckTerminate(task)
			return hec.Retry(task)
		default:
			return res
		}
	})
	miniMiddleware := newMiniMiddleware(miniMiddlewareFunc, s.config)
	myMT.SetResultMiddlewares(miniMiddleware)
	finalMtResult, _ := myMT.Run(context.Background(), uint(s.config.Threads))
	dirScanResults.Target = s.Url
	if hyperMaxRetryCheckEC.GetErrorNum() > s.config.DirScanMaxRetryLimit || hyperRootCheckEC.GetErrorNum() > s.config.DirScanMaxRootCheckRetryLimit {
		if hyperRootCheckEC.GetErrorType() == "" {
			dirScanResults.ErrorUpperLimitExitType = NetworkUnreachableError
		} else {
			dirScanResults.ErrorUpperLimitExitType = hyperRootCheckEC.GetErrorType()
		}
	}
	for _, v := range finalMtResult {
		if v != nil {
			r := v.(*dirScanResult)
			dirScanResults.Paths.Common = append(dirScanResults.Paths.Common, r.Path)
		}
	}
	s.scanJsMap(&dirScanResults)
	return dirScanResults
}

func (s *DirScanner) sendRequest(t *dirScanTargetTask) *dirScanResult {
	//num++
	tUrl := t.TargetUrl
	if strings.HasSuffix(tUrl, "/") {

		tUrl = strings.Trim(tUrl, "/")
	}
	target := tUrl + trimPath(t.Path)
	resp, err := s.SendRequest("", base.Param{}, base.RequestOptions{
		Redirect:    false,
		Retry:       true,
		RetryMaxNum: 3,
		RequestSingleUseOption: base.RequestSingleUseOption{
			Url:     target,
			Method:  base.GET,
			Headers: nil,
		},
	})
	defer func() {
		if resp != nil && resp.RawResponse != nil && resp.RawResponse.Body != nil {
			resp.RawResponse.Body.Close()
		}
	}()
	if err != nil {
		//fmt.Println(err)
		if strings.Contains(err.Error(), "Timeout") {
			return &dirScanResult{
				Code:   TIMEOUT,
				Target: t.TargetUrl,
				Path:   t.Path,
			}
		} else {
			return &dirScanResult{
				Code:   UNKNOWN,
				Target: t.TargetUrl,
				Path:   t.Path,
			}
		}
	} else {
		if t.IsTimeOut {
			return &dirScanResult{
				IsEverTimeout: true,
				Code:          resp.StatusCode,
				Target:        t.TargetUrl,
				Path:          t.Path,
			}
		}
		return &dirScanResult{
			IsRandomCheckPath: t.IsRandomCheckPath,
			Code:              resp.StatusCode,
			Target:            t.TargetUrl,
			Path:              t.Path,
		}

	}
}

func (s *DirScanner) scanJsMap(results *DirScanResults) {
	resp, err := s.SendRequest("", base.Param{}, base.DefaultRequestOptionsWithRetry)
	if err != nil {
		return
	}
	jsFile := matchJs(resp.Body)
	for _, v := range jsFile {
		var path string
		if strings.HasPrefix(v, "/") {
			path = v
		} else {
			path = "/" + v
		}
		res, err := s.SendRequest("", base.Param{}, base.RequestOptions{
			Redirect:    false,
			Retry:       true,
			RetryMaxNum: 3,
			RequestSingleUseOption: base.RequestSingleUseOption{
				Url:     s.Url + path,
				Method:  base.GET,
				Headers: nil,
			},
		})

		if err != nil {
			continue
		}
		jsMaps := matchJsMap(res.Body)
		results.Paths.Jsmap = append(results.Paths.Jsmap, jsMaps...)
	}
}

func trimPath(string2 string) string {
	trimmed := strings.Trim(string2, " \t\n\r")
	if strings.HasPrefix(trimmed, "/") {
		return trimmed
	} else {
		return "/" + trimmed
	}
}

func matchJsMap(body string) []string {
	regex := regexp.MustCompile(`app\.(\w+)\.js\.map`)
	results := regex.FindAllString(body, -1)
	return utils.RemoveDuplicateStrings(results)
}
func matchJs(body string) []string {
	var jsPath []string
	regex := regexp.MustCompile(`".*\.js"`)
	results := regex.FindAllString(body, -1)
	for _, v := range results {
		if !strings.Contains(v, "http://") && !strings.Contains(v, "https://") {
			jsPath = append(jsPath, strings.ReplaceAll(v, "\"", ""))
		}
	}
	return utils.RemoveDuplicateStrings(jsPath)
}
