package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	glog "github.com/labstack/gommon/log"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func newObservedEchoLogger() (*echoLogger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.DebugLevel)
	return newEchoLogger(zap.New(core).Sugar()), logs
}

func TestEchoLoggerLevels(t *testing.T) {
	logger, logs := newObservedEchoLogger()

	logger.Debugf("debug %s", "msg")
	logger.Infof("info %s", "msg")
	logger.Warnf("warn %s", "msg")
	logger.Errorf("error %s", "msg")
	// gommon's level-less Print maps to info.
	logger.Print("print msg")

	entries := logs.All()
	require.Len(t, entries, 5)
	require.Equal(t, zapcore.DebugLevel, entries[0].Level)
	require.Equal(t, "debug msg", entries[0].Message)
	require.Equal(t, zapcore.InfoLevel, entries[1].Level)
	require.Equal(t, zapcore.WarnLevel, entries[2].Level)
	require.Equal(t, zapcore.ErrorLevel, entries[3].Level)
	require.Equal(t, zapcore.InfoLevel, entries[4].Level)
}

func TestEchoLoggerJSONFields(t *testing.T) {
	logger, logs := newObservedEchoLogger()

	logger.Errorj(glog.JSON{"file": "app.go", "line": 42})

	entries := logs.All()
	require.Len(t, entries, 1)
	require.Equal(t, zapcore.ErrorLevel, entries[0].Level)
	fields := entries[0].ContextMap()
	require.Equal(t, "app.go", fields["file"])
	require.EqualValues(t, 42, fields["line"])
}

// Fatal must not os.Exit like gommon does — a library must not be able to
// kill the daemon. It logs at error level and panics instead.
func TestEchoLoggerFatalPanics(t *testing.T) {
	logger, logs := newObservedEchoLogger()

	require.PanicsWithValue(t, "fatal problem", func() {
		logger.Fatalf("fatal %s", "problem")
	})
	require.PanicsWithValue(t, "panic problem", func() {
		logger.Panicf("panic %s", "problem")
	})

	entries := logs.All()
	require.Len(t, entries, 2)
	require.Equal(t, zapcore.ErrorLevel, entries[0].Level)
	require.Equal(t, "fatal problem", entries[0].Message)
	require.Equal(t, zapcore.ErrorLevel, entries[1].Level)
}

// The original motivation for the adapter: a panic inside a handler must
// leave a stack trace in awl's logs, not on a console the process may not
// have.
func TestEchoLoggerPanicStackReachesZap(t *testing.T) {
	logger, logs := newObservedEchoLogger()

	e := echo.New()
	e.Logger = logger
	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{
		LogLevel: glog.ERROR,
	}))
	e.GET("/boom", func(c echo.Context) error {
		panic("kaboom")
	})

	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	entries := logs.FilterLevelExact(zapcore.ErrorLevel).All()
	require.Len(t, entries, 1)
	require.Contains(t, entries[0].Message, "PANIC RECOVER")
	require.Contains(t, entries[0].Message, "kaboom")
	require.Contains(t, entries[0].Message, "goroutine")
}
