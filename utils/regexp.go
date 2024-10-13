package utils

import "regexp"

func MatchAnyOfRegexp(regexps []string, match string) (bool, string) {
	for _, value := range regexps {
		regex := regexp.MustCompile(value)
		if regex.MatchString(match) {
			return true, value
		}
	}

	return false, ""
}
