package proto

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrorCode is the stable machine-readable failure taxonomy. It mirrors the
// codes the existing NasSimHub agent already returns so Core can treat a Node
// failure and a QDC507 failure with one piece of handling code.
type ErrorCode string

const (
	ErrorInvalidArgument    ErrorCode = "invalid_argument"
	ErrorNotFound           ErrorCode = "not_found"
	ErrorConflict           ErrorCode = "conflict"
	ErrorNotSupported       ErrorCode = "not_supported"
	ErrorUnauthenticated    ErrorCode = "unauthenticated"
	ErrorPermissionDenied   ErrorCode = "permission_denied"
	ErrorFailedPrecondition ErrorCode = "failed_precondition"
	ErrorNetworkRejected    ErrorCode = "network_rejected"
	ErrorUnavailable        ErrorCode = "unavailable"
	ErrorInternal           ErrorCode = "internal"
)

// HTTPStatus maps a code onto the status the Node returns. Keeping the mapping
// here rather than in the HTTP layer means Core can reconstruct the code from
// a status when a proxy has mangled the body.
func (c ErrorCode) HTTPStatus() int {
	switch c {
	case ErrorInvalidArgument:
		return http.StatusBadRequest
	case ErrorNotFound:
		return http.StatusNotFound
	case ErrorConflict:
		return http.StatusConflict
	case ErrorNotSupported:
		return http.StatusNotImplemented
	case ErrorUnauthenticated:
		return http.StatusUnauthorized
	case ErrorPermissionDenied:
		return http.StatusForbidden
	case ErrorFailedPrecondition:
		return http.StatusPreconditionFailed
	case ErrorNetworkRejected:
		return http.StatusUnprocessableEntity
	case ErrorUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// OperationError is the error every Node operation returns.
type OperationError struct {
	Code      ErrorCode
	Operation string
	Message   string
	Cause     error
}

func (e *OperationError) Error() string {
	switch {
	case e.Cause == nil && e.Operation == "":
		return e.Message
	case e.Cause == nil:
		return fmt.Sprintf("%s: %s", e.Operation, e.Message)
	case e.Operation == "":
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	default:
		return fmt.Sprintf("%s: %s: %v", e.Operation, e.Message, e.Cause)
	}
}

func (e *OperationError) Unwrap() error { return e.Cause }

// AsOperationError extracts a coded error from a wrapped chain.
func AsOperationError(err error) (*OperationError, bool) {
	var operationError *OperationError
	if !errors.As(err, &operationError) {
		return nil, false
	}
	return operationError, true
}

// CodeOf reports the code of err, or ErrorInternal when err carries none.
func CodeOf(err error) ErrorCode {
	if operationError, ok := AsOperationError(err); ok {
		return operationError.Code
	}
	return ErrorInternal
}

func newError(code ErrorCode, operation, message string, cause error) error {
	return &OperationError{Code: code, Operation: operation, Message: message, Cause: cause}
}

func InvalidArgument(operation, message string) error {
	return newError(ErrorInvalidArgument, operation, message, nil)
}

func NotFound(operation, message string) error {
	return newError(ErrorNotFound, operation, message, nil)
}

func Conflict(operation, message string) error {
	return newError(ErrorConflict, operation, message, nil)
}

func NotSupported(operation, message string) error {
	return newError(ErrorNotSupported, operation, message, nil)
}

func Unauthenticated(operation, message string) error {
	return newError(ErrorUnauthenticated, operation, message, nil)
}

func PermissionDenied(operation, message string) error {
	return newError(ErrorPermissionDenied, operation, message, nil)
}

func FailedPrecondition(operation, message string) error {
	return newError(ErrorFailedPrecondition, operation, message, nil)
}

func NetworkRejected(operation, message string, cause error) error {
	return newError(ErrorNetworkRejected, operation, message, cause)
}

func Unavailable(operation, message string, cause error) error {
	return newError(ErrorUnavailable, operation, message, cause)
}

func Internal(operation, message string, cause error) error {
	return newError(ErrorInternal, operation, message, cause)
}

// APIError is the JSON body of any non-2xx Node response.
type APIError struct {
	Code      ErrorCode `json:"code"`
	Operation string    `json:"operation,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	Message   string    `json:"message"`
}

// ErrorBody wraps APIError so the payload is self-describing.
type ErrorBody struct {
	Error APIError `json:"error"`
}
