package commandInject

import (
	"context"
	"fmt"
	"github.com/B9O2/Inspector/useful"
	"github.com/B9O2/Multitasking"
	"github.com/OctopusScan/webVulScanEngine/base"
	"github.com/OctopusScan/webVulScanEngine/conf"
	"github.com/OctopusScan/webVulScanEngine/result"
	. "github.com/OctopusScan/webVulScanEngine/runtime"
	"github.com/OctopusScan/webVulScanEngine/scanner/attacks/injectAttacks"
	"github.com/OctopusScan/webVulScanEngine/utils"
	"strconv"
	"strings"
	"time"
)

type commandInjectPayload struct {
	method     base.HttpMethod
	isEcho     bool
	echoResult string
	payload    string
	sleepTime  float64
}

type CommandInject struct {
	injectAttacks.BaseInject
	normalResponseTime float64
	payloads           []commandInjectPayload
	config             conf.CommandInjectConfig
}

func NewCommandInject(target base.BaseTarget, config conf.CommandInjectConfig) *CommandInject {
	return &CommandInject{
		BaseInject: injectAttacks.BaseInject{
			BaseTarget: target,
		},
		config: config,
	}
}

func (c *CommandInject) prePare() bool {
	err, time := c.GetNormalRespondTime()
	if err != nil {
		MainInsp.Print(useful.ERROR, FileName("commandInject.go"), useful.Text(fmt.Sprintf("[Plugin CommandInject] getNormalResponseError")))
		return false
	}
	c.normalResponseTime = time
	return true
}

func (c *CommandInject) StartAttack() ([]result.VulMessage, error) {
	ok := c.PrePareVariations(string(result.CommandInject))
	if !ok {
		return []result.VulMessage{}, nil
	}
	ok = c.prePare()
	if !ok {
		return []result.VulMessage{}, nil
	}
	return c.checkInject()
}

func (c *CommandInject) checkInject() ([]result.VulMessage, error) {
	c.generatePayload()
	var checkRes []result.VulMessage
	commandCheckMT := Multitasking.NewMultitasking("commandCheckMT", nil)
	commandCheckMT.Register(
		func(dc Multitasking.DistributeController) {
			for _, v := range c.payloads {
				dc.AddTask(v)
			}
		},
		func(ec Multitasking.ExecuteController, a any) any {
			p := a.(commandInjectPayload)
			for _, param := range c.Variations.Params {
				var requsetTime float64
				var response *base.Response
				var err error
				start := time.Now() // 记录开始时间
				response, err = c.SendRequest(p.payload, param, base.DefaultRequestOptionsWithoutRetry)
				if err != nil {
					continue
				}
				requsetTime = float64(time.Since(start).Nanoseconds()) / float64(time.Millisecond) // 计算耗时
				if p.isEcho {
					if strings.Contains(response.Body, p.echoResult) {
						return result.VulMessage{
							DataType: result.WebVul,
							VulnData: result.VulnData{
								CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
								VulnType:    result.CommandInjection,
								VulnSubType: result.CommandInjectionWithEcho,
								Target:      c.Url,
								Method:      c.Method,
								Param:       param.Name,
								Payload:     p.payload,
								CURLCommand: "",
								Description: "",
								Request:     response.RequestDump,
								Response:    response.ResponseDump,
							},
							Plugin: result.CommandInject,
							Level:  result.Critical,
						}
					}
				} else {
					if c.config.UsingTimeBase {
						if requsetTime > c.normalResponseTime+p.sleepTime*1000-500 {
							return result.VulMessage{
								DataType: result.WebVul,
								VulnData: result.VulnData{
									CreateTime:  time.Now().Format("2006-01-02 15:04:05"),
									VulnType:    result.CommandInjection,
									VulnSubType: result.CommandInjectionWithTime,
									Target:      c.Url,
									Method:      c.Method,
									Param:       param.Name,
									Payload:     p.payload,
									CURLCommand: "",
									Description: "",
									Request:     response.RequestDump,
									Response:    response.ResponseDump,
								},
								Plugin: result.CommandInject,
								Level:  result.Critical,
							}
						}
					}
				}
			}
			return nil
		})
	run, err := commandCheckMT.Run(context.Background(), c.config.ScanThreads)
	if err != nil {
		return checkRes, err
	}
	for _, v := range run {
		if v != nil {
			checkRes = append(checkRes, v.(result.VulMessage))
		}
	}
	return checkRes, nil
}
func (c *CommandInject) generatePayload() {
	for _, closeType := range injectAttacks.CommandCloseType {
		for _, lk := range injectAttacks.CommandLinkType {
			//var payload string
			num1 := utils.RandNumber(1000000, 9999999)
			num2 := utils.RandNumber(1000000, 9999999)
			timeout := utils.RandNumber(4, 8)
			expressResult := num1 + num2

			payloadWithLinuxEcho := closeType + lk + strings.ReplaceAll(injectAttacks.CommandInjectWithLinuxEcho, "{expression}", fmt.Sprintf("%s+%s", strconv.Itoa(num1), strconv.Itoa(num2)))
			payloadWithLinuxNoEcho := closeType + lk + strings.ReplaceAll(injectAttacks.CommandInjectWithLinuxNoEcho, "{timeout}", strconv.Itoa(timeout))
			payloadWithLinuxEchoAndBacktick := closeType + lk + strings.ReplaceAll(fmt.Sprintf("`%s`", injectAttacks.CommandInjectWithLinuxEcho), "{expression}", fmt.Sprintf("%s+%s", strconv.Itoa(num1), strconv.Itoa(num2)))
			payloadWithLinuxNoEchoAndBacktick := closeType + lk + strings.ReplaceAll(fmt.Sprintf("`%s`", injectAttacks.CommandInjectWithLinuxNoEcho), "{timeout}", strconv.Itoa(timeout))
			payloadWithWindowsEcho := closeType + lk + strings.ReplaceAll(injectAttacks.CommandInjectWithWindowsEcho, "{expression}", fmt.Sprintf("%s+%s", strconv.Itoa(num1), strconv.Itoa(num2)))
			payloadWithWindowsNoEcho := closeType + lk + strings.ReplaceAll(injectAttacks.CommandInjectWithWindowsNoEcho, "{timeout}", strconv.Itoa(timeout))

			//payload = c.Variations.setPayloadByIndex(index, c.Url, payload, c.Method)

			c.payloads = append(c.payloads, commandInjectPayload{
				method:     c.Method,
				isEcho:     true,
				echoResult: strconv.Itoa(expressResult),
				payload:    payloadWithLinuxEcho,
			})

			c.payloads = append(c.payloads, commandInjectPayload{
				method:     c.Method,
				isEcho:     true,
				echoResult: strconv.Itoa(expressResult),
				payload:    payloadWithLinuxEchoAndBacktick,
			})

			c.payloads = append(c.payloads, commandInjectPayload{
				method:     c.Method,
				isEcho:     true,
				echoResult: strconv.Itoa(expressResult),
				payload:    payloadWithWindowsEcho,
			})
			if c.config.UsingTimeBase {
				c.payloads = append(c.payloads, commandInjectPayload{
					sleepTime:  float64(timeout - 1),
					method:     c.Method,
					isEcho:     false,
					echoResult: "",
					payload:    payloadWithLinuxNoEcho,
				})
				c.payloads = append(c.payloads, commandInjectPayload{
					sleepTime:  float64(timeout - 1),
					method:     c.Method,
					isEcho:     false,
					echoResult: "",
					payload:    payloadWithLinuxNoEchoAndBacktick,
				})
				c.payloads = append(c.payloads, commandInjectPayload{
					sleepTime:  float64(timeout - 1),
					method:     c.Method,
					isEcho:     false,
					echoResult: "",
					payload:    payloadWithWindowsNoEcho,
				})
			}

		}
	}
}
