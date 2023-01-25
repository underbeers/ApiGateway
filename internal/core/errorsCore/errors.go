package errorsCore

import "errors"

var (
	ErrCantWriteFile     = errors.New("can't write file")
	ErrTokenExpired      = errors.New("token has expired")
	ErrInvalidToken      = errors.New("invalid Authorization token provided")
	ErrReadResponseBody  = errors.New("can't read response body")
	ErrCloseResponseBody = errors.New("can't close response body")
	ErrParseHandleURL    = errors.New("error while parse url for handle")
	ErrParseHeader       = errors.New("error while parseheader")
)
