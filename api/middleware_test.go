package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// logRecord is one captured logf call.
type logRecord struct {
	status  int
	message string
}

func newMiddlewareTestEcho() (*echo.Echo, *[]logRecord) {
	records := &[]logRecord{}
	e := echo.New()
	e.Use(errorLogMiddlewareLogf(func(status int, format string, args ...any) {
		*records = append(*records, logRecord{status: status, message: fmt.Sprintf(format, args...)})
	}))
	return e, records
}

func doRequest(e *echo.Echo, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestErrorLogMiddleware(t *testing.T) {
	apiPath := V0Prefix + "test"

	t.Run("success response is passed through and not logged", func(t *testing.T) {
		e, records := newMiddlewareTestEcho()
		bigBody := strings.Repeat("x", 3*errorBodyLogLimit)
		e.GET(apiPath, func(c echo.Context) error {
			return c.String(http.StatusOK, bigBody)
		})

		rec := doRequest(e, http.MethodGet, apiPath)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, bigBody, rec.Body.String())
		require.Empty(t, *records)
	})

	t.Run("handler-written 4xx on API path is logged with body", func(t *testing.T) {
		e, records := newMiddlewareTestEcho()
		e.POST(apiPath, func(c echo.Context) error {
			return c.JSON(http.StatusBadRequest, ErrorMessage("invalid peer id"))
		})

		rec := doRequest(e, http.MethodPost, apiPath)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Len(t, *records, 1)
		require.Equal(t, http.StatusBadRequest, (*records)[0].status)
		require.Contains(t, (*records)[0].message, "POST "+apiPath+": 400:")
		require.Contains(t, (*records)[0].message, "invalid peer id")
	})

	t.Run("4xx outside API prefix is not logged", func(t *testing.T) {
		e, records := newMiddlewareTestEcho()
		e.GET("/static.js", func(c echo.Context) error {
			return c.String(http.StatusNotFound, "404 page not found")
		})

		rec := doRequest(e, http.MethodGet, "/static.js")
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Empty(t, *records)
	})

	t.Run("5xx outside API prefix is still logged", func(t *testing.T) {
		e, records := newMiddlewareTestEcho()
		e.GET("/broken", func(c echo.Context) error {
			return c.JSON(http.StatusInternalServerError, ErrorMessage("boom"))
		})

		doRequest(e, http.MethodGet, "/broken")
		require.Len(t, *records, 1)
		require.Equal(t, http.StatusInternalServerError, (*records)[0].status)
	})

	t.Run("echo HTTPError is logged with its status and rendered by echo", func(t *testing.T) {
		e, records := newMiddlewareTestEcho()
		e.GET(apiPath, func(c echo.Context) error {
			return echo.NewHTTPError(http.StatusUnauthorized, "bad credentials")
		})

		rec := doRequest(e, http.MethodGet, apiPath)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Contains(t, rec.Body.String(), "bad credentials")
		require.Len(t, *records, 1)
		require.Equal(t, http.StatusUnauthorized, (*records)[0].status)
		require.Contains(t, (*records)[0].message, "bad credentials")
	})

	t.Run("plain error from handler is logged as 500", func(t *testing.T) {
		e, records := newMiddlewareTestEcho()
		e.GET(apiPath, func(c echo.Context) error {
			return fmt.Errorf("database exploded")
		})

		rec := doRequest(e, http.MethodGet, apiPath)
		require.Equal(t, http.StatusInternalServerError, rec.Code)
		require.Len(t, *records, 1)
		require.Equal(t, http.StatusInternalServerError, (*records)[0].status)
		require.Contains(t, (*records)[0].message, "database exploded")
	})

	t.Run("route not found under API prefix is logged", func(t *testing.T) {
		e, records := newMiddlewareTestEcho()

		rec := doRequest(e, http.MethodGet, V0Prefix+"no/such/route")
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Len(t, *records, 1)
		require.Equal(t, http.StatusNotFound, (*records)[0].status)
	})

	t.Run("oversized error body is truncated in the log, intact on the wire", func(t *testing.T) {
		e, records := newMiddlewareTestEcho()
		bigError := strings.Repeat("e", 2*errorBodyLogLimit)
		e.GET(apiPath, func(c echo.Context) error {
			return c.String(http.StatusBadRequest, bigError)
		})

		rec := doRequest(e, http.MethodGet, apiPath)
		require.Equal(t, bigError, rec.Body.String())
		require.Len(t, *records, 1)
		message := (*records)[0].message
		require.Contains(t, message, "(body truncated)")
		// message = "GET <path>: 400: <capped body> (body truncated)" — the
		// captured part must be capped at errorBodyLogLimit, not the full 2x.
		require.Less(t, len(message), errorBodyLogLimit+200)
	})

	t.Run("committed response with error returned is logged once", func(t *testing.T) {
		e, records := newMiddlewareTestEcho()
		e.GET(apiPath, func(c echo.Context) error {
			_ = c.JSON(http.StatusBadRequest, ErrorMessage("written and returned"))
			return fmt.Errorf("handler also returned an error")
		})

		rec := doRequest(e, http.MethodGet, apiPath)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		require.Len(t, *records, 1)
		require.Contains(t, (*records)[0].message, "written and returned")
	})

	t.Run("Flush is passed through to the underlying writer", func(t *testing.T) {
		e, _ := newMiddlewareTestEcho()
		e.GET(apiPath, func(c echo.Context) error {
			_ = c.String(http.StatusOK, "chunk")
			c.Response().Flush()
			return nil
		})

		rec := doRequest(e, http.MethodGet, apiPath)
		require.Equal(t, http.StatusOK, rec.Code)
		require.True(t, rec.Flushed)
	})
}
