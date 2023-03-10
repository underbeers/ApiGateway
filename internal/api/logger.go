package api

import (
	"context"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"net/http"
	"os"
	"time"
)

type responseWriter struct {
	http.ResponseWriter
	code int
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.code = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

const logPermissions = 0o640

func NewLogger(isLocal bool) *zap.Logger {
	loggerConfig := zap.NewProductionEncoderConfig()
	loggerConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	fileEncoder := zapcore.NewJSONEncoder(loggerConfig)
	timeStamp := time.Now().Format("02-01-2006")
	logFile, err := os.OpenFile(fmt.Sprintf("./logs/apigateway-%s.log", timeStamp),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, logPermissions)
	if err != nil {
		log.Printf("Error while creating NewLogger %s", err.Error())
	}
	writer := zapcore.AddSync(logFile)
	defaultLogLevel := zapcore.DebugLevel
	if isLocal {
		consoleEncoder := zapcore.NewConsoleEncoder(loggerConfig)
		core := zapcore.NewTee(
			zapcore.NewCore(fileEncoder, writer, defaultLogLevel),
			zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), defaultLogLevel),
		)
		logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

		return logger
	}
	core := zapcore.NewTee(
		zapcore.NewCore(fileEncoder, writer, defaultLogLevel),
	)
	logger := zap.New(core, zap.AddCaller())

	return logger
}

func (gw *gateWay) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{w, http.StatusOK}
		gw.Logger.Info("started", zap.String("Method", r.Method), zap.String("URL", r.RequestURI),
			zap.String("X-request-ID", r.Header.Get(requestID)))
		start := time.Now()
		next.ServeHTTP(rw, r)
		const (
			logFieldsCount = 6
			serverError    = 500
			userError      = 400
			completed      = "completed"
		)
		logLine := make([]zap.Field, 0, logFieldsCount)
		logLine = append(logLine, zap.String("Method", r.Method),
			zap.Int("Code", rw.code), zap.String("Status", http.StatusText(rw.code)),
			zap.String("URL", r.Header.Get("RedirectURL")+r.RequestURI), zap.String(requestID, r.Header.Get(requestID)),
			zap.Duration("took", time.Since(start)))
		switch {
		case rw.code >= serverError:
			gw.Logger.Error(completed, logLine...)
		case rw.code >= userError:
			gw.Logger.Warn(completed, logLine...)
		default:
			gw.Logger.Info(completed, logLine...)
		}
	})
}

func (gw *gateWay) respond(w http.ResponseWriter, code int, data interface{}) {
	w.WriteHeader(code)
	if data != nil {
		err := json.NewEncoder(w).Encode(data)
		if err != nil {
			gw.Logger.Error("failed to encode json", zap.Error(err))
		}
	}
}

func (gw *gateWay) warning(w http.ResponseWriter, code int, err error, msg string) {
	gw.respond(w, code, map[string]string{"message": msg})
	gw.Logger.Warn(err.Error())
}

func (gw *gateWay) error(w http.ResponseWriter, code int, err error, ctx context.Context) { //nolint:unused
	gw.respond(w, code, map[string]string{"message": err.Error()})
	gw.Logger.Error("", zap.Any(requestID, ctx.Value(requestID)), zap.String("err", err.Error()))
}
