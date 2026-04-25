package types

import (
	"fmt"
	"strings"
)

type ErrorCode string

const (
	ErrCodeSuccess              ErrorCode = "SUCCESS"
	ErrCodeInternalError        ErrorCode = "INTERNAL_ERROR"
	ErrCodeInvalidParam         ErrorCode = "INVALID_PARAM"
	ErrCodeInvalidRequest       ErrorCode = "INVALID_REQUEST"
	ErrCodeInvalidQuery         ErrorCode = "INVALID_QUERY"
	ErrCodeNotFound             ErrorCode = "NOT_FOUND"
	ErrCodeEventNotFound        ErrorCode = "EVENT_NOT_FOUND"
	ErrCodeAlertNotFound        ErrorCode = "ALERT_NOT_FOUND"
	ErrCodeAlertAlreadyResolved ErrorCode = "ALERT_ALREADY_RESOLVED"
	ErrCodeUnauthorized         ErrorCode = "UNAUTHORIZED"
	ErrCodeParseFailed          ErrorCode = "PARSE_FAILED"
	ErrCodeImportFailed         ErrorCode = "IMPORT_FAILED"
	ErrCodeFileNotFound         ErrorCode = "FILE_NOT_FOUND"
	ErrCodeFileLocked           ErrorCode = "FILE_LOCKED"
	ErrCodeInvalidFormat        ErrorCode = "INVALID_FORMAT"
	ErrCodeDBError              ErrorCode = "DB_ERROR"
	ErrCodeDBReadOnly           ErrorCode = "DB_READ_ONLY"
	ErrCodeRuleInvalid          ErrorCode = "RULE_INVALID"
	ErrCodeRuleNotFound         ErrorCode = "RULE_NOT_FOUND"
	ErrCodeRuleDisabled         ErrorCode = "RULE_DISABLED"
	ErrCodeSearchFailed         ErrorCode = "SEARCH_FAILED"
	ErrCodeResultTooLarge       ErrorCode = "RESULT_TOO_LARGE"
	ErrCodeHashMismatch         ErrorCode = "HASH_MISMATCH"
	ErrCodeSignatureInvalid     ErrorCode = "SIGNATURE_INVALID"
	ErrCodeNotSupported         ErrorCode = "NOT_SUPPORTED"
)

type WinError struct {
	Code    ErrorCode
	Message string
	Cause   error
}

func (e *WinError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *WinError) Unwrap() error {
	return e.Cause
}

func (e *WinError) Is(target error) bool {
	if t, ok := target.(*WinError); ok {
		return t.Code == e.Code
	}
	return false
}

func NewWinError(code ErrorCode, message string) *WinError {
	return &WinError{
		Code:    code,
		Message: message,
	}
}

func NewWinErrorWithCause(code ErrorCode, message string, cause error) *WinError {
	return &WinError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

func WrapError(code ErrorCode, message string, err error) *WinError {
	if err == nil {
		return NewWinError(code, message)
	}
	return NewWinErrorWithCause(code, message, err)
}

func IsSuccess(err error) bool {
	if err == nil {
		return true
	}
	if e, ok := err.(*WinError); ok {
		return e.Code == ErrCodeSuccess
	}
	return false
}

func IsNotFound(err error) bool {
	if e, ok := err.(*WinError); ok {
		return e.Code == ErrCodeNotFound
	}
	return false
}

func IsInvalidParam(err error) bool {
	if e, ok := err.(*WinError); ok {
		return e.Code == ErrCodeInvalidParam
	}
	return false
}

func IsInternalError(err error) bool {
	if e, ok := err.(*WinError); ok {
		return e.Code == ErrCodeInternalError
	}
	return false
}

type ParseError struct {
	*WinError
	FilePath string
	Line     int
}

func (e *ParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s: %s at %s:%d", e.Code, e.Message, e.FilePath, e.Line)
	}
	return fmt.Sprintf("%s: %s in %s", e.Code, e.Message, e.FilePath)
}

func NewParseError(filePath string, message string) *ParseError {
	return &ParseError{
		WinError: NewWinError(ErrCodeParseFailed, message),
		FilePath: filePath,
	}
}

func NewParseErrorAtLine(filePath string, line int, message string) *ParseError {
	return &ParseError{
		WinError: NewWinError(ErrCodeParseFailed, message),
		FilePath: filePath,
		Line:     line,
	}
}

type ValidationError struct {
	*WinError
	Field string
	Value interface{}
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s (field: %s, value: %v)", e.Code, e.Message, e.Field, e.Value)
}

func NewValidationError(field, message string, value interface{}) *ValidationError {
	return &ValidationError{
		WinError: NewWinError(ErrCodeInvalidParam, message),
		Field:    field,
		Value:    value,
	}
}

type AggregateError struct {
	Errors []error
}

func (e *AggregateError) Error() string {
	if len(e.Errors) == 0 {
		return "no errors"
	}
	var msgs []string
	for _, err := range e.Errors {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

func (e *AggregateError) IsZero() bool {
	return len(e.Errors) == 0
}

func NewAggregateError() *AggregateError {
	return &AggregateError{
		Errors: make([]error, 0),
	}
}

func (e *AggregateError) Add(err error) {
	if err != nil {
		e.Errors = append(e.Errors, err)
	}
}

func (e *AggregateError) AddAll(errs ...error) {
	for _, err := range errs {
		e.Add(err)
	}
}
