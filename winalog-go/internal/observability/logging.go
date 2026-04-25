package observability

import (
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

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

	var encoder zapcore.Encoder
	var encoderConfig zapcore.EncoderConfig

	if config.Format == FormatJSON {
		encoderConfig = zap.NewProductionEncoderConfig()
		encoderConfig.TimeKey = "timestamp"
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoderConfig = zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
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

	var writeSyncer zapcore.WriteSyncer
	if config.OutputPath == "stdout" || config.OutputPath == "" {
		writeSyncer = zapcore.AddSync(os.Stdout)
	} else {
		file, err := os.OpenFile(config.OutputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		writeSyncer = zapcore.NewMultiWriteSyncer(
			zapcore.AddSync(os.Stdout),
			zapcore.AddSync(file),
		)
	}

	core := zapcore.NewCore(encoder, writeSyncer, level)
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return &Logger{
		Logger: logger,
		config: config,
	}, nil
}

func (l *Logger) Sync() error {
	return l.Logger.Sync()
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
