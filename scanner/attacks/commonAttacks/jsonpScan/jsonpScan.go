package jsonpScan

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/result"
	"github.com/robertkrimen/otto/ast"
	"github.com/robertkrimen/otto/parser"
	"net/url"
	"regexp"
	"time"
)

type JsonpScan struct {
	base.BaseTarget
}

func (j *JsonpScan) StartAttack() ([]result.VulMessage, error) {
	ok, resp, _ := j.checkSenseJsonp(j.Url)
	if ok {
		return []result.VulMessage{{
			DataType: result.WebVul,
			VulnData: result.VulnData{
				CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
				VulnType:    result.JsonpHijacking,
				VulnSubType: result.JsonpHiJacking,
				Target:      j.Url,
				//ip:          "",
				Method:      j.Method,
				Param:       "",
				Payload:     "",
				CURLCommand: "",
				Description: "",
				Request:     resp.RequestDump,
				Response:    resp.ResponseDump,
			},
			Plugin: result.JsonpScan,
			Level:  result.Medium,
		}}, nil
	}
	return []result.VulMessage{}, nil
}

func NewJsonpScanner(target base.BaseTarget) *JsonpScan {
	return &JsonpScan{target}
}

func (j *JsonpScan) checkSenseJsonp(jsUrl string) (bool, *base.Response, error) {
	queryMap, domainString, err := urlParser(jsUrl)
	if err != nil {
		return false, nil, err
	}

	isCallback, callbackFuncName, err := checkJSIsCallback(queryMap)

	if isCallback {
		//	referer： host 请求
		resp, err := j.getJsResponse(jsUrl, domainString)
		if err != nil {
			return false, nil, err
		}
		isJsonpNormal, err := checkJsRespAst(resp.Body, callbackFuncName)
		if err != nil {
			return false, nil, err
		}
		// 如果包含敏感字段 将 referer 置空 再请求一次
		if isJsonpNormal {
			resp, err := j.getJsResponse(jsUrl, "")
			if err != nil {
				return false, nil, err
			}
			isJsonp, err := checkJsRespAst(resp.Body, callbackFuncName)
			if err != nil {
				return false, nil, err
			}

			return isJsonp, resp, nil
		}

	}
	return false, nil, nil
}

func urlParser(jsUrl string) (url.Values, string, error) {
	urlp, err := url.Parse(jsUrl)
	if err != nil {
		return nil, "", err
	}
	// 拼接原始referer
	domainString := urlp.Scheme + "://" + urlp.Host
	return urlp.Query(), domainString, nil
}

func checkJSIsCallback(queryMap url.Values) (bool, string, error) {
	var re = regexp.MustCompile(`(?m)(?i)(callback)|(jsonp)|(^cb$)|(function)`)
	for k, v := range queryMap {
		regResult := re.FindAllString(k, -1)
		if len(regResult) > 0 && len(v) > 0 {
			return true, v[0], nil
		}
	}
	return false, "", nil
}

func checkIsSensitiveKey(key string) (bool, error) {
	var re = regexp.MustCompile(`(?m)(?i)(uid)|(userid)|(user_id)|(nin)|(name)|(username)|(nick)`)
	regResult := re.FindAllString(key, -1)
	if len(regResult) > 0 {
		return true, nil
	}
	return false, nil
}

func (j *JsonpScan) getJsResponse(jsUrl string, referer string) (*base.Response, error) {
	req, err := j.SendRequest("", base.Param{}, base.RequestOptions{
		Redirect:    false,
		Retry:       true,
		RetryMaxNum: 3,
		RequestSingleUseOption: base.RequestSingleUseOption{
			Url:     jsUrl,
			Method:  base.GET,
			Headers: map[string]interface{}{"Referer": referer},
		},
	})
	if err != nil {
		return nil, err
	}
	return req, nil
}

func checkJsRespAst(content string, funcName string) (bool, error) {
	// 解析js语句，生成 *ast.Program 或 ErrorList
	program, err := parser.ParseFile(nil, "", content, 0)
	if err != nil {
		return false, err
	}
	if len(program.Body) > 0 {
		statement := program.Body[0]
		expression := statement.(*ast.ExpressionStatement).Expression
		expName := expression.(*ast.CallExpression).Callee.(*ast.Identifier).Name
		// 表达式中函数名与query函数名不一致 直接返回false
		if funcName != expName {
			return false, err
		}
		argList := expression.(*ast.CallExpression).ArgumentList
		for _, arg := range argList {
			result := dealAstExpression(arg)
			if result != true {
				continue
			}
			return result, nil
		}
	}
	//ast树为空 直接返回
	return false, nil
}

func dealAstExpression(expression ast.Expression) bool {
	objectLiteral, isObjectLiteral := expression.(*ast.ObjectLiteral)
	if isObjectLiteral {
		values := objectLiteral.Value
		for _, value := range values {
			result := dealAstProperty(value)
			if result != true {
				continue
			}
			return result
		}
	}
	return false
}
func dealAstProperty(value ast.Property) bool {
	secondLevelValue := value.Value
	// 表达式中是数组/对象的 递归
	objectLiteral, isObjectLiteral := secondLevelValue.(*ast.ObjectLiteral)
	arrayLiteral, isArrayLiteral := secondLevelValue.(*ast.ArrayLiteral)
	stringLiteral, isStringLiteral := secondLevelValue.(*ast.StringLiteral)
	numberLiteral, isNumberLiteral := secondLevelValue.(*ast.NumberLiteral)
	if isObjectLiteral {
		thirdLevelValue := objectLiteral.Value
		for _, v := range thirdLevelValue {
			dealAstProperty(v)
		}
	} else if isArrayLiteral {
		thirdLevelValue := arrayLiteral.Value
		for _, v := range thirdLevelValue {
			dealAstExpression(v)
		}
	} else if isStringLiteral {
		// 表达式中value为字符串/数字的 才会检测key value
		thirdLevelValue := stringLiteral.Value
		isSensitiveKey, _ := checkIsSensitiveKey(value.Key)
		if isSensitiveKey && thirdLevelValue != "" {
			return true
		}
	} else if isNumberLiteral {
		thirdLevelValue := numberLiteral.Value
		isSensitiveKey, _ := checkIsSensitiveKey(value.Key)
		if isSensitiveKey && thirdLevelValue != 0 {
			return true
		}
	}
	return false
}
