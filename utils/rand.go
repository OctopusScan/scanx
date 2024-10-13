package utils

import (
	uuid "github.com/satori/go.uuid"
	"golang.org/x/exp/rand"
	"strings"
	"time"
	"unicode"
)

const lower = "abcdefghijklmnopqrstuvwxyz"
const lowerUpper = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const numberLowerUpper = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const numberLower = "0123456789abcdefghijklmnopqrstuvwxyz"

const letterIdxBits = 6
const letterIdxMask = 1<<letterIdxBits - 1
const letterIdxMax = 63 / letterIdxBits

func init() {
	rand.Seed(uint64(time.Now().Unix()))
}

func RandFromChoices(n int, choices string) string {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(uint64(time.Now().UnixNano())))
	for i, cache, remain := n-1, r.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = r.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(choices) {
			b[i] = choices[idx]
			i--
		}
		cache >>= letterIdxBits
	}
	return string(b)
}

func RandNumber(n int, m int) int {
	u1 := uuid.NewV4().String()
	uuidString := strings.Split(u1, "-")[0]
	var seed int64
	for _, c := range uuidString {
		seed += int64(c)
	}
	rand.NewSource(uint64(seed))
	return rand.Intn(m-n) + n
}

// RandLetters 随机小写字母
func RandLetters(n int) string {
	return RandFromChoices(n, lower)
}

// RandLetterNumbers 随机大小写字母和数字
func RandLetterNumbers(n int) string {
	return RandFromChoices(n, numberLowerUpper)
}

// RandString 随机大小写字母
func RandString(n int) string {
	return RandFromChoices(n, lowerUpper)
}

// RandLowLetterNumber 随机小写字母和数字
func RandLowLetterNumber(n int) string {
	return RandFromChoices(n, numberLower)
}

// RandomUpper 随机改字母大小写
func RandomUpper(s string) string {
	r := []rune(s)
	for {
		pos := rand.Intn(len(r))
		if unicode.IsLower(r[pos]) {
			r[pos] = unicode.ToUpper(r[pos])
			break
		} else if unicode.IsUpper(r[pos]) {
			r[pos] = unicode.ToLower(r[pos])
			break
		}
	}

	for i := 0; i < len(r); i++ {
		if !unicode.IsLetter(r[i]) {
			continue
		}
		if rand.Intn(2) == 0 {
			r[i] = unicode.ToLower(r[i])
		} else {
			r[i] = unicode.ToUpper(r[i])
		}
	}
	return string(r)
}
