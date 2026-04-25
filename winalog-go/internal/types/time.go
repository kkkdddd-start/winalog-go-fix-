package types

import (
	"fmt"
	"strings"
	"time"
)

type TimeFilter struct {
	Start time.Time
	End   time.Time
}

func (tf *TimeFilter) IsValid() bool {
	return tf.End.After(tf.Start)
}

func (tf *TimeFilter) Duration() time.Duration {
	return tf.End.Sub(tf.Start)
}

func ParseTimeFilter(input string) (*TimeFilter, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}

	parts := strings.Split(input, ",")
	if len(parts) == 2 {
		startDuration, startErr := parseDuration(parts[0])
		endDuration, endErr := parseDuration(parts[1])

		if startErr == nil && endErr == nil {
			start := time.Now().Add(-startDuration)
			end := time.Now().Add(-endDuration)
			if end.After(start) {
				return &TimeFilter{Start: start, End: end}, nil
			}
			return &TimeFilter{Start: end, End: start}, nil
		}

		if startErr == nil {
			end, err := parseTimeValue(parts[1])
			if err != nil {
				return nil, err
			}
			start := time.Now().Add(-startDuration)
			if end.After(start) {
				return &TimeFilter{Start: start, End: end}, nil
			}
			return &TimeFilter{Start: end, End: start}, nil
		}

		if endErr == nil {
			start, err := parseTimeValue(parts[0])
			if err != nil {
				return nil, err
			}
			end := time.Now().Add(-endDuration)
			if end.After(start) {
				return &TimeFilter{Start: start, End: end}, nil
			}
			return &TimeFilter{Start: end, End: start}, nil
		}

		start, err := parseTimeValue(parts[0])
		if err != nil {
			return nil, err
		}
		end, err := parseTimeValue(parts[1])
		if err != nil {
			return nil, err
		}
		if end.After(start) {
			return &TimeFilter{Start: start, End: end}, nil
		}
		return &TimeFilter{Start: end, End: start}, nil
	}

	if strings.Contains(input, "T") || strings.HasPrefix(input, "20") {
		t, err := parseTimeValue(input)
		if err != nil {
			return nil, err
		}
		return &TimeFilter{Start: t, End: time.Now()}, nil
	}

	input = normalizeDuration(input)

	dur, err := time.ParseDuration(input)
	if err != nil {
		return nil, err
	}
	return &TimeFilter{
		Start: time.Now().Add(-dur),
		End:   time.Now(),
	}, nil
}

func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	s = normalizeDuration(s)
	return time.ParseDuration(s)
}

func normalizeDuration(s string) string {
	s = strings.ToLower(s)
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		hours := 24 * parseInt(days)
		return fmt.Sprintf("%dh", hours)
	}
	return s
}

func parseInt(s string) int {
	var result int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		}
	}
	return result
}

func parseTimeValue(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"01/02/2006 15:04:05",
		"01/02/2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, &time.ParseError{
		Layout:     strings.Join([]string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02"}, "|"),
		Value:      s,
		LayoutElem: "",
		ValueElem:  s,
		Message:    "unsupported time format",
	}
}

func ParseTimeWindow(timeWindow string) (time.Duration, error) {
	return time.ParseDuration(timeWindow)
}
