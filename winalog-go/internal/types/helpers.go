package types

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

func containsInt32(slice []int32, item int32) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func matchesRegex(value interface{}, pattern string) bool {
	str, ok := value.(string)
	if !ok {
		return false
	}
	matched, err := regexp.MatchString(pattern, str)
	if err != nil {
		return false
	}
	return matched
}

func compareValues(a, b interface{}) int {
	switch av := a.(type) {
	case int:
		switch bv := b.(type) {
		case int:
			if av > bv {
				return 1
			} else if av < bv {
				return -1
			}
			return 0
		case float64:
			if float64(av) > bv {
				return 1
			} else if float64(av) < bv {
				return -1
			}
			return 0
		case string:
			bi, err := strconv.Atoi(bv)
			if err != nil {
				return 1
			}
			if av > bi {
				return 1
			} else if av < bi {
				return -1
			}
			return 0
		}
	case float64:
		switch bv := b.(type) {
		case float64:
			if av > bv {
				return 1
			} else if av < bv {
				return -1
			}
			return 0
		case int:
			if av > float64(bv) {
				return 1
			} else if av < float64(bv) {
				return -1
			}
			return 0
		case string:
			bf, err := strconv.ParseFloat(bv, 64)
			if err != nil {
				return 1
			}
			if av > bf {
				return 1
			} else if av < bf {
				return -1
			}
			return 0
		}
	case string:
		switch bv := b.(type) {
		case string:
			if strings.Compare(av, bv) > 0 {
				return 1
			} else if strings.Compare(av, bv) < 0 {
				return -1
			}
			return 0
		case int:
			ai, err := strconv.Atoi(av)
			if err != nil {
				return 1
			}
			if ai > bv {
				return 1
			} else if ai < bv {
				return -1
			}
			return 0
		case float64:
			af, err := strconv.ParseFloat(av, 64)
			if err != nil {
				return 1
			}
			if af > bv {
				return 1
			} else if af < bv {
				return -1
			}
			return 0
		}
	case time.Time:
		switch bv := b.(type) {
		case time.Time:
			if av.After(bv) {
				return 1
			} else if av.Before(bv) {
				return -1
			}
			return 0
		}
	}
	return 0
}

func normalizeString(s string) string {
	return strings.TrimSpace(strings.ToLower(s))
}

func isPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
