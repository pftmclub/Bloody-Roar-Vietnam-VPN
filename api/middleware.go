package api

import (
	"bytes"
	"errors"
	"net/http"
	"strings"

	"github.com/ipfs/go-log/v2"
	"github.com/labstack/echo/v4"
)

// errorBodyLogLimit caps how much of an error response body is captured for
// logging. Error bodies are small JSON objects; the cap only guards against a
// pathological handler.
const errorBodyLogLimit = 4 * 1024

// errorLogMiddleware logs every error response, which would otherwise exist
// only in the UI banner that showed it: handlers write errors directly with
// c.JSON(4xx/5xx, ...), so from echo's point of view they are successful
// responses and no framework hook sees them. Must be registered first (as the
// outermost middleware) — errors from inner middleware (basic auth 401s,
// panics recovered to 500s) are only visible to middleware outside of them.
//
// 5xx are logged everywhere as errors; 4xx as warnings and only under the API
// prefix — outside it they are browser noise (static file misses, the basic
// auth 401 every browser session starts with).
func errorLogMiddleware(logger *log.ZapEventLogger) echo.MiddlewareFunc {
	return errorLogMiddlewareLogf(func(status int, format string, args ...any) {
		if status >= http.StatusInternalServerError {
			logger.Errorf(format, args...)
		} else {
			logger.Warnf(format, args...)
		}
	})
}

// errorLogMiddlewareLogf is errorLogMiddleware with the log destination
// injected, so tests can assert on emitted records.
func errorLogMiddlewareLogf(logf func(status int, format string, args ...any)) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			w := &errorCaptureWriter{ResponseWriter: c.Response().Writer}
			c.Response().Writer = w

			err := next(c)
			req := c.Request()

			// An error heading to echo's HTTPErrorHandler: it is rendered
			// after this middleware returns, so the capture below never sees
			// its body — log the error value itself. If the response is
			// already committed, the write went through the capture writer
			// and the branch below reports it instead.
			if err != nil && !c.Response().Committed {
				status := http.StatusInternalServerError
				if httpErr, ok := errors.AsType[*echo.HTTPError](err); ok {
					status = httpErr.Code
				}
				if shouldLogErrorResponse(status, req.URL.Path) {
					logf(status, "%s %s: %d: %v", req.Method, req.URL.Path, status, err)
				}
				return err
			}

			if w.status >= 400 && shouldLogErrorResponse(w.status, req.URL.Path) {
				body := bytes.TrimSpace(w.body.Bytes())
				truncated := ""
				if w.truncated {
					truncated = " (body truncated)"
				}
				logf(w.status, "%s %s: %d: %s%s", req.Method, req.URL.Path, w.status, body, truncated)
			}
			return err
		}
	}
}

func shouldLogErrorResponse(status int, path string) bool {
	return status >= http.StatusInternalServerError || strings.HasPrefix(path, V0Prefix)
}

// errorCaptureWriter passes everything through to the underlying
// ResponseWriter and additionally keeps a copy of the body — but only once
// the status is known to be an error, so success responses (log dumps,
// metrics scrapes, pprof profiles) are never buffered.
type errorCaptureWriter struct {
	http.ResponseWriter
	status    int
	body      bytes.Buffer
	truncated bool
}

func (w *errorCaptureWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *errorCaptureWriter) Write(b []byte) (int, error) {
	if w.status >= 400 {
		free := errorBodyLogLimit - w.body.Len()
		if len(b) <= free {
			w.body.Write(b)
		} else {
			w.body.Write(b[:free])
			w.truncated = true
		}
	}
	return w.ResponseWriter.Write(b)
}

// Flush keeps streaming endpoints (pprof profiles) working: echo's
// Response.Flush type-asserts the underlying writer to http.Flusher and would
// panic on a wrapper without it.
func (w *errorCaptureWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer's optional
// interfaces.
func (w *errorCaptureWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
