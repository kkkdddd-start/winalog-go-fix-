package observability

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DebugEnabled 返回是否启用调试日志
var DebugEnabled = os.Getenv("WINALOG_DEBUG") == "true"

// DebugPrintf 条件输出调试日志，仅当 WINALOG_DEBUG=true 时输出
func DebugPrintf(format string, args ...interface{}) {
	if DebugEnabled {
		log.Printf(format, args...)
	}
}

// Debugf 返回格式化字符串，用于调试信息拼接
func Debugf(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

// PanicRecover 标准 panic 恢复处理，输出错误日志和堆栈跟踪
func PanicRecover(module string, fields ...zap.Field) {
	if r := recover(); r != nil {
		stack := string(debug.Stack())
		allFields := append(fields,
			zap.String("module", module),
			zap.Any("panic", r),
			zap.String("stack", stack),
		)
		Error("Panic recovered", allFields...)
	}
}

// logFileWriterAdapter 将 LogFile 适配为 zapcore.WriteSyncer，使用同一个文件句柄
var logFileWriter zapcore.WriteSyncer
var logFileWriterOnce sync.Once

func getLogWriter() zapcore.WriteSyncer {
	logFileWriterOnce.Do(func() {
		lf := GetLogFile()
		if lf != nil {
			logFileWriter = zapcore.AddSync(lf)
		}
	})
	return logFileWriter
}

type LoggerConfig struct {
	Level      string
	Format     string
	OutputPath string
}

type Logger struct {
	*zap.Logger
	config *LoggerConfig
}

var defaultLogger *Logger

const (
	FormatJSON    = "json"
	FormatConsole = "console"
)

func NewLogger(config *LoggerConfig) (*Logger, error) {
	if config == nil {
		config = &LoggerConfig{
			Level:      "info",
			Format:     FormatConsole,
			OutputPath: "stdout",
		}
	}

	level := zapcore.InfoLevel
	switch config.Level {
	case "debug":
		level = zapcore.DebugLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	case "fatal":
		level = zapcore.FatalLevel
	}

	// stdout: console 格式（人类可读）
	stdoutEncoderConfig := zap.NewDevelopmentEncoderConfig()
	stdoutEncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	stdoutEncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	stdoutCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(stdoutEncoderConfig),
		zapcore.AddSync(os.Stdout),
		level,
	)

	// 日志文件: JSON 格式（便于 UI 解析）
	var cores []zapcore.Core
	cores = append(cores, stdoutCore)

	if fileWriter := getLogWriter(); fileWriter != nil {
		fileEncoderConfig := zap.NewProductionEncoderConfig()
		fileEncoderConfig.TimeKey = "timestamp"
		fileEncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		fileEncoderConfig.LevelKey = "level"
		fileEncoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
		fileEncoderConfig.MessageKey = "message"
		fileCore := zapcore.NewCore(
			zapcore.NewJSONEncoder(fileEncoderConfig),
			fileWriter,
			level,
		)
		cores = append(cores, fileCore)
	}

	logger := zap.New(zapcore.NewTee(cores...), zap.AddCaller(), zap.AddCallerSkip(1))

	return &Logger{
		Logger: logger,
		config: config,
	}, nil
}

func (l *Logger) Sync() error {
	if l.Logger != nil {
		return l.Logger.Sync()
	}
	return nil
}

func (l *Logger) GetConfig() *LoggerConfig {
	return l.config
}

func InitDefaultLogger(config *LoggerConfig) error {
	logger, err := NewLogger(config)
	if err != nil {
		return err
	}
	defaultLogger = logger
	return nil
}

func GetLogger() *Logger {
	if defaultLogger == nil {
		defaultLogger, _ = NewLogger(nil)
	}
	return defaultLogger
}

// SetLogLevel 动态修改日志级别，无需重启
func SetLogLevel(level string) error {
	l := GetLogger()
	if l == nil {
		return fmt.Errorf("logger not initialized")
	}

	var newLevel zapcore.Level
	switch strings.ToLower(level) {
	case "debug":
		newLevel = zapcore.DebugLevel
	case "info":
		newLevel = zapcore.InfoLevel
	case "warn":
		newLevel = zapcore.WarnLevel
	case "error":
		newLevel = zapcore.ErrorLevel
	case "fatal":
		newLevel = zapcore.FatalLevel
	default:
		return fmt.Errorf("unknown log level: %s", level)
	}

	// 使用 atomic 替换（zap 的 core 支持原子更新）
	stdoutCfg := zap.NewDevelopmentEncoderConfig()
	stdoutCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	stdoutCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder

	fileCfg := zap.NewProductionEncoderConfig()
	fileCfg.TimeKey = "timestamp"
	fileCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	fileCfg.LevelKey = "level"
	fileCfg.EncodeLevel = zapcore.LowercaseLevelEncoder
	fileCfg.MessageKey = "message"

	l.Logger = l.Logger.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core {
		levelEnabler := zap.NewAtomicLevelAt(newLevel)
		var cores []zapcore.Core
		cores = append(cores, zapcore.NewCore(
			zapcore.NewConsoleEncoder(stdoutCfg),
			zapcore.AddSync(os.Stdout),
			levelEnabler,
		))
		if fileWriter := getLogWriter(); fileWriter != nil {
			cores = append(cores, zapcore.NewCore(
				zapcore.NewJSONEncoder(fileCfg),
				fileWriter,
				levelEnabler,
			))
		}
		return zapcore.NewTee(cores...)
	}))

	defaultLogger = l
	return nil
}

func (l *Logger) Debug(msg string, fields ...zap.Field) {
	l.Logger.Debug(msg, fields...)
}

func (l *Logger) Info(msg string, fields ...zap.Field) {
	l.Logger.Info(msg, fields...)
}

func (l *Logger) Warn(msg string, fields ...zap.Field) {
	l.Logger.Warn(msg, fields...)
}

func (l *Logger) Error(msg string, fields ...zap.Field) {
	l.Logger.Error(msg, fields...)
}

func (l *Logger) Fatal(msg string, fields ...zap.Field) {
	l.Logger.Fatal(msg, fields...)
}

func Debug(msg string, fields ...zap.Field) {
	GetLogger().Debug(msg, fields...)
}

func Info(msg string, fields ...zap.Field) {
	GetLogger().Info(msg, fields...)
}

func Warn(msg string, fields ...zap.Field) {
	GetLogger().Warn(msg, fields...)
}

func Error(msg string, fields ...zap.Field) {
	GetLogger().Error(msg, fields...)
}

func Fatal(msg string, fields ...zap.Field) {
	GetLogger().Fatal(msg, fields...)
}

func With(fields ...zap.Field) *zap.Logger {
	return GetLogger().With(fields...)
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Caller    string    `json:"caller,omitempty"`
}

func (l *LogEntry) ToZapFields() []zap.Field {
	return []zap.Field{
		zap.String("level", l.Level),
		zap.String("message", l.Message),
		zap.String("caller", l.Caller),
		zap.Time("timestamp", l.Timestamp),
	}
}

type LogGroup struct {
	logger *Logger
	fields []zap.Field
}

func NewLogGroup(logger *Logger) *LogGroup {
	return &LogGroup{
		logger: logger,
		fields: []zap.Field{},
	}
}

func (g *LogGroup) WithField(key string, value interface{}) *LogGroup {
	g.fields = append(g.fields, zap.Any(key, value))
	return g
}

func (g *LogGroup) WithFields(fields ...zap.Field) *LogGroup {
	g.fields = append(g.fields, fields...)
	return g
}

func (g *LogGroup) Debug(msg string) {
	g.logger.Debug(msg, g.fields...)
}

func (g *LogGroup) Info(msg string) {
	g.logger.Info(msg, g.fields...)
}

func (g *LogGroup) Warn(msg string) {
	g.logger.Warn(msg, g.fields...)
}

func (g *LogGroup) Error(msg string) {
	g.logger.Error(msg, g.fields...)
}

func (g *LogGroup) Fatal(msg string) {
	g.logger.Fatal(msg, g.fields...)
}

type StructuredLogger struct {
	logger *zap.Logger
	module string
}

func NewStructuredLogger(module string) *StructuredLogger {
	return &StructuredLogger{
		logger: GetLogger().Logger,
		module: module,
	}
}

func (s *StructuredLogger) With(fields ...zap.Field) *StructuredLogger {
	newLogger := s.logger.With(fields...)
	return &StructuredLogger{
		logger: newLogger,
		module: s.module,
	}
}

func (s *StructuredLogger) WithModule(module string) *StructuredLogger {
	return &StructuredLogger{
		logger: s.logger,
		module: module,
	}
}

func (s *StructuredLogger) Debug(msg string, fields ...zap.Field) {
	fields = append(fields, zap.String("module", s.module))
	s.logger.Debug(msg, fields...)
}

func (s *StructuredLogger) Info(msg string, fields ...zap.Field) {
	fields = append(fields, zap.String("module", s.module))
	s.logger.Info(msg, fields...)
}

func (s *StructuredLogger) Warn(msg string, fields ...zap.Field) {
	fields = append(fields, zap.String("module", s.module))
	s.logger.Warn(msg, fields...)
}

func (s *StructuredLogger) Error(msg string, fields ...zap.Field) {
	fields = append(fields, zap.String("module", s.module))
	s.logger.Error(msg, fields...)
}

func (s *StructuredLogger) Fatal(msg string, fields ...zap.Field) {
	fields = append(fields, zap.String("module", s.module))
	s.logger.Fatal(msg, fields...)
}
