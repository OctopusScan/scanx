package sqlInject

import (
	"fmt"
	"github.com/B9O2/Inspector/useful"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/result"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/OctopusScan/webVulScanEngine/utils"
	"github.com/thoas/go-funk"
	"golang.org/x/net/html"
	"strconv"
	"strings"
	"time"
)

type SqlInject struct {
	*BaseSqlInject
	config conf.DbsScanConfig
}

func (s *SqlInject) StartAttack() ([]result.VulMessage, error) {
	ok := s.PrePareVariations("sqlInject")
	if !ok {
		return nil, nil
	}
	s.typeConvertCheck()
	var sqlRes []sqlScanType
	sqlRes = s.errorMessageCheck()

	//bool盲注误报率较高
	//if len(sqlRes) == 0 {
	//	sqlRes = s.boolCheck()
	//}

	if s.config.UsingTimeBase {
		sqlRes = append(sqlRes, s.timeBaseCheck()...)
	}
	var vulMessage []result.VulMessage
	for _, v := range sqlRes {
		var vulnSubType result.VulSubType
		if v.isTimeBase {
			vulnSubType = result.SqlInjectBaseTime
		} else {
			vulnSubType = result.SqlInjectBaseError
		}
		vulMessage = append(vulMessage, result.VulMessage{
			DataType: "web_vul",
			Plugin:   result.SqlInject,
			VulnData: result.VulnData{
				VulnType:    result.SqlInjection,
				VulnSubType: vulnSubType,
				CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
				Target:      s.Url,
				Method:      s.Method,
				//ip:          "",
				Param:       v.paramName,
				Request:     v.requestDump,
				Response:    v.responseDump,
				Payload:     v.payload,
				Description: fmt.Sprintf("%s SQL Injection:]", v.injectType),
			},
			Level: result.Critical,
		})
		if base.SimpleRes {
			break
		}
	}
	return vulMessage, nil
}

func (s *SqlInject) typeConvertCheck() {
	var params []base.Param
	for _, v := range s.Variations.Params {
		var response *base.Response
		var err error
		response, err = s.SendRequest(utils.RandString(4), v, base.DefaultRequestOptionsWithRetry)
		if err != nil {
			continue
		}
		hasCovert := false
		for _, fe := range formatExceptionStrings {
			if strings.Contains(response.Body, fe) {
				hasCovert = true
				MainInsp.Print(useful.WARN, useful.Text(fmt.Sprintf("%s检测到转型,参数%s不存在注入", s.Url, v.Name)))
				break
			}
		}
		if !hasCovert {
			params = append(params, v)
		}
	}
	s.Variations.Params = params
}

func (s *SqlInject) errorMessageCheck() []sqlScanType {
	var sqlRes []sqlScanType
	for _, v := range s.Variations.Params {
		for _, e := range closeType {
			var response *base.Response
			var err error
			payload := utils.RandString(4) + e
			response, err = s.SendRequest(payload, v, base.DefaultRequestOptionsWithRetry)
			if err != nil {
				continue
			}
			for dbms, regexps := range dbmsErrors {
				if math, _ := utils.MatchAnyOfRegexp(regexps, response.ResponseDump); math {
					sqlRes = append(sqlRes, sqlScanType{
						paramName:    v.Name,
						payload:      payload,
						dbms:         dbms,
						requestDump:  response.RequestDump,
						responseDump: response.ResponseDump,
						injectType:   "Error Base",
					})
					if base.SimpleRes {
						return sqlRes
					}
				}
			}
		}
	}
	return sqlRes
}

func (s *SqlInject) boolCheck() []sqlScanType {
	var sqlRes []sqlScanType
	boolCloseType := closeType
	boolCloseType = append(boolCloseType, "")
	var lo []string
	//var checklo []string
	//checklo = append(checklo, and...)
	lo = append(lo, or...)
	for _, v := range s.Variations.Params {
		//获取对比模板,正常请求的和可能出现错误信息的模板
		responseTemplate, err := s.getTemplateResponse(v)
		//responseErrorTemplate := s.getErrorTemplateResponse(v)
		if err != nil {
			continue
		}
		for _, c := range boolCloseType {
			for _, sp := range space {
				for _, a := range lo {
					for _, an := range annotator {
						payload := fmt.Sprintf("%d%s%s%s%s%d=%d%s", funk.RandomInt(10000000, 99999999), c, sp, a, sp, funk.RandomInt(10000000, 99999999), funk.RandomInt(10000000, 99999999), an)
						var response *base.Response
						response, err = s.SendRequest(payload, v, base.DefaultRequestOptionsWithRetry)
						if err != nil {
							continue
						}
						//if strings.Contains(response.Body, "No results matched. Try Again") {
						//	fmt.Println(11)
						//}
						//hanmingInstance := utils.StrDiffBySimHash(responseTemplate, utils.DiffContent([]string{responseTemplate, response.Body}))

						//如果和正常请求模板相似,证明起码没有出错,或者闭合公式成
						isSim := s.simTemplates([]string{responseTemplate}, s.cleanHtmlTag(response.Body), true)
						if isSim {
							var checkResponse *base.Response
							checkVal := funk.RandomInt(10000000, 99999999)
							checkPayload := fmt.Sprintf("%d%s%s%s%s%d=%d%s", funk.RandomInt(10000000, 99999999), c, sp, a, sp, checkVal, checkVal, an)
							checkResponse, err = s.SendRequest(checkPayload, v, base.DefaultRequestOptionsWithRetry)
							if err != nil {
								continue
							}
							//hanmingInstance = utils.StrDiffBySimHash(responseTemplate, utils.DiffContent([]string{responseTemplate, checkResponse.Body}))
							//重新将payload or后面的设置为true,在和error情况对比,如果不和error相似,证明就是注入payload
							isSim = s.simTemplates([]string{responseTemplate}, s.cleanHtmlTag(checkResponse.Body), false)
							if !isSim {
								sqlRes = append(sqlRes, sqlScanType{
									paramName:    v.Name,
									payload:      checkPayload,
									responseDump: checkResponse.ResponseDump,
									requestDump:  checkResponse.RequestDump,
									dbms:         "",
									injectType:   "Boolean Base",
								})
								if base.SimpleRes {
									return sqlRes
								}
								break
							}
						}
					}
				}
			}
		}
	}
	return sqlRes
}

func (s *SqlInject) getTemplateResponse(param base.Param) (string, error) {
	var responses []string
	var values []string
	values = append(values, strconv.Itoa(funk.RandomInt(1000, 9999)), strconv.Itoa(funk.RandomInt(1000, 9999)))
	for _, v := range values {
		response, err := s.GetResponse(param, v)
		if err != nil {
			return "", err
		}
		responses = append(responses, s.cleanHtmlTag(response.Body))
	}

	return utils.DiffContent(responses), nil

}
func (s *SqlInject) simTemplates(responseTemplate []string, responseBody string, first bool) bool {
	for _, v := range responseTemplate {
		hanmingInstance := utils.StrDiffBySimHash(v, utils.DiffContent([]string{v, responseBody}))
		if hanmingInstance < 4 {
			//是否是第一次比对,第一次比对只是为了判断闭合是否成功
			if first {
				return true
			}
			//如果不是第一次比对,证明开始了误报检测,如果走到了这里,证明非常相似,需要判断和原来的页面是不是一致的,如果一致则不能证明bool盲注的or 肯定条件生效
			recheck := utils.StrDiffBySimHash(responseBody, v)
			if recheck != 0 {
				return false
			}
			return true
		}
	}
	return false
}
func (s *SqlInject) getErrorTemplateResponse(param base.Param) []string {
	var errTemplates []string
	for _, v := range closeType {
		resp, err := s.GetResponse(param, strconv.Itoa(funk.RandomInt(1000, 9999))+v)
		if err != nil {
			continue
		}
		resp2, err := s.GetResponse(param, strconv.Itoa(funk.RandomInt(1000, 9999))+v)
		if err != nil {
			continue
		}
		errTemplates = append(errTemplates, utils.DiffContent([]string{s.cleanHtmlTag(resp.Body), s.cleanHtmlTag(resp2.Body)}))
	}
	return errTemplates
}

func (s *SqlInject) timeBaseCheck() []sqlScanType {
	var sqlRes []sqlScanType
	timeBaseCloseType := closeType
	timeBaseCloseType = append(timeBaseCloseType, "")
	err, normalTime := s.GetNormalRespondTime()
	var lo []string
	lo = append(lo, and...)
	lo = append(lo, or...)
	var response *base.Response
	var payloads []string
	if err != nil {
		MainInsp.Print(useful.ERROR, useful.Text(fmt.Sprintf("time base check error:%s", err.Error())))
	}

	for _, v := range s.Variations.Params {
		payload0 := strings.ReplaceAll("if(now()=sysdate(),sleep(time),0)", "time", strconv.FormatInt(int64(normalTime+3), 10))
		payloads = append(payloads, payload0)
		for _, ct := range timeBaseCloseType {
			for _, sp := range space {
				for _, a := range lo {
					for _, dt := range delayTimeFunc {
						for _, an := range annotator {
							payload := fmt.Sprintf("%d%s%s%s%s%s%s", utils.RandNumber(1000, 9999), ct, sp, a, sp, strings.ReplaceAll(dt, "{{time}}", strconv.FormatInt(int64(normalTime+3), 10)), an)
							payloads = append(payloads, payload)
						}
					}
				}
			}
		}
		for _, p := range payloads {
			start := time.Now() // 记录开始时间
			response, err = s.SendRequest(p, v, base.DefaultRequestOptionsWithRetry)
			elapsed := time.Since(start) // 计算耗时
			if err != nil {
				if strings.Contains(err.Error(), "Timeout") {
					sqlRes = append(sqlRes, sqlScanType{
						isTimeBase:   true,
						paramName:    v.Name,
						payload:      p,
						requestDump:  response.RequestDump,
						responseDump: response.ResponseDump,
						dbms:         "",

						injectType: "Time Base",
					})
					return sqlRes
				}
				continue
			}
			if elapsed.Seconds()-1 > normalTime {
				sqlRes = append(sqlRes, sqlScanType{
					isTimeBase:   true,
					paramName:    v.Name,
					payload:      p,
					requestDump:  response.RequestDump,
					responseDump: response.ResponseDump,
					dbms:         "",

					injectType: "Time Base",
				})
				return sqlRes
			}
		}
	}
	return sqlRes
}

func (s *SqlInject) cleanHtmlTag(resp string) string {
	doc, err := html.Parse(strings.NewReader(resp))
	if err != nil {
		return ""
	}
	return getText(doc)

}

func getText(node *html.Node) string {
	var text string
	if node.Type == html.TextNode {
		text += node.Data
	}
	for c := node.FirstChild; c != nil; c = c.NextSibling {
		text += getText(c)
	}
	return text
}

func NewSqlInject(target base.BaseTarget, config conf.DbsScanConfig) *SqlInject {
	return &SqlInject{
		BaseSqlInject: NewBaseSqlInject(target),
		config:        config,
	}
}
