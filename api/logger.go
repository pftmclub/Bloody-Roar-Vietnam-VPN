package api

import (
	"fmt"
	"io"

	"github.com/labstack/echo/v4"
	glog "github.com/labstack/gommon/log"
	"go.uber.org/zap"
)

// echoLogger adapts our zap-based logger to the echo.Logger interface, so
// echo's internal logs — recovered panic stack traces, "response already
// committed", failures to send an error response — land in awl's log file and
// ring buffer instead of a console.
//
// Echo core only ever calls Print/Warn/Error/Errorf plus the Output/Prefix/
// SetLevel plumbing; the rest of the interface is implemented for
// completeness.
type echoLogger struct {
	l *zap.SugaredLogger
}

var _ echo.Logger = (*echoLogger)(nil)

// newEchoLogger wraps l for echo. The caller-skip makes zap report echo's
// call site instead of this adapter.
func newEchoLogger(l *zap.SugaredLogger) *echoLogger {
	return &echoLogger{l: l.WithOptions(zap.AddCallerSkip(1))}
}

// Output/Prefix/level plumbing: filtering and destinations are governed by
// the go-log config, not by echo, so the setters are no-ops. Level reports
// DEBUG so echo never suppresses a record before it reaches zap. Output is
// only used by echo for its startup banner colorer (hidden in awl) and the
// initial StdLogger (overridden in setupRouter).

func (e *echoLogger) Output() io.Writer     { return io.Discard }
func (e *echoLogger) SetOutput(_ io.Writer) {}
func (e *echoLogger) Prefix() string        { return "" }
func (e *echoLogger) SetPrefix(_ string)    {}
func (e *echoLogger) Level() glog.Lvl       { return glog.DEBUG }
func (e *echoLogger) SetLevel(_ glog.Lvl)   {}
func (e *echoLogger) SetHeader(_ string)    {}

func (e *echoLogger) Print(i ...any)                    { e.l.Info(i...) }
func (e *echoLogger) Printf(format string, args ...any) { e.l.Infof(format, args...) }
func (e *echoLogger) Printj(j glog.JSON)                { e.l.Infow("", jsonFields(j)...) }

func (e *echoLogger) Debug(i ...any)                    { e.l.Debug(i...) }
func (e *echoLogger) Debugf(format string, args ...any) { e.l.Debugf(format, args...) }
func (e *echoLogger) Debugj(j glog.JSON)                { e.l.Debugw("", jsonFields(j)...) }

func (e *echoLogger) Info(i ...any)                    { e.l.Info(i...) }
func (e *echoLogger) Infof(format string, args ...any) { e.l.Infof(format, args...) }
func (e *echoLogger) Infoj(j glog.JSON)                { e.l.Infow("", jsonFields(j)...) }

func (e *echoLogger) Warn(i ...any)                    { e.l.Warn(i...) }
func (e *echoLogger) Warnf(format string, args ...any) { e.l.Warnf(format, args...) }
func (e *echoLogger) Warnj(j glog.JSON)                { e.l.Warnw("", jsonFields(j)...) }

func (e *echoLogger) Error(i ...any)                    { e.l.Error(i...) }
func (e *echoLogger) Errorf(format string, args ...any) { e.l.Errorf(format, args...) }
func (e *echoLogger) Errorj(j glog.JSON)                { e.l.Errorw("", jsonFields(j)...) }

// Fatal* log at error level and panic instead of gommon's os.Exit: a library
// must not be able to kill the P2P daemon bypassing deferred cleanup, and a
// panic keeps the "does not return" contract while staying catchable by
// Recover.

func (e *echoLogger) Fatal(i ...any) {
	e.l.Error(i...)
	panic(fmt.Sprint(i...))
}

func (e *echoLogger) Fatalf(format string, args ...any) {
	e.l.Errorf(format, args...)
	panic(fmt.Sprintf(format, args...))
}

func (e *echoLogger) Fatalj(j glog.JSON) {
	e.l.Errorw("", jsonFields(j)...)
	panic(fmt.Sprintf("%v", j))
}

func (e *echoLogger) Panic(i ...any) {
	e.l.Error(i...)
	panic(fmt.Sprint(i...))
}

func (e *echoLogger) Panicf(format string, args ...any) {
	e.l.Errorf(format, args...)
	panic(fmt.Sprintf(format, args...))
}

func (e *echoLogger) Panicj(j glog.JSON) {
	e.l.Errorw("", jsonFields(j)...)
	panic(fmt.Sprintf("%v", j))
}

// jsonFields flattens a gommon structured-log map into zap key-value pairs.
func jsonFields(j glog.JSON) []any {
	fields := make([]any, 0, len(j)*2)
	for k, v := range j {
		fields = append(fields, k, v)
	}
	return fields
}
