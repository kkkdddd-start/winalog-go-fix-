package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.Logger
	mu sync.RWMutex
}

var (
	defaultLogger *Logger
	once          sync.Once
)

func GetLogger() *Logger {
	once.Do(func() {
		defaultLogger = NewLogger("info", "")
	})
	return defaultLogger
}

func NewLogger(level, logFile string) *Logger {
	var config zap.Config

	if logFile != "" {
		config = zap.NewProductionConfig()
		config.OutputPaths = []string{logFile, "stderr"}
	} else {
		config = zap.NewDevelopmentConfig()
		config.OutputPaths = []string{"stderr"}
	}

	switch level {
	case "debug":
		config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	case "info":
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	case "warn":
		config.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
	case "error":
		config.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	case "fatal":
		config.Level = zap.NewAtomicLevelAt(zapcore.FatalLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	zapLogger, err := config.Build()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize logger: %v", err))
	}

	return &Logger{
		Logger: zapLogger,
	}
}

type LumberjackSink struct {
	*os.File
	mu         sync.Mutex
	maxSize    int
	maxAge     int
	maxBackups int
	filename   string
}

func NewLumberjackSink(filename string, maxSize, maxAge, maxBackups int) (*LumberjackSink, error) {
	dir := filepath.Dir(filename)
	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory: %w", err)
		}
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &LumberjackSink{
		File:       file,
		maxSize:    maxSize,
		maxAge:     maxAge,
		maxBackups: maxBackups,
		filename:   filename,
	}, nil
}

func (s *LumberjackSink) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.maxSize > 0 {
		stat, err := s.File.Stat()
		if err == nil && int(stat.Size()) >= s.maxSize*1024*1024 {
			if err := s.rotate(); err != nil {
				return 0, err
			}
		}
	}

	return s.File.Write(p)
}

func (s *LumberjackSink) rotate() error {
	s.File.Close()

	now := time.Now()
	newName := fmt.Sprintf("%s.%s", s.filename, now.Format("20060102150405"))
	if err := os.Rename(s.filename, newName); err != nil {
		return fmt.Errorf("failed to rotate log file: %w", err)
	}

	var err error
	s.File, err = os.OpenFile(s.filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to create new log file: %w", err)
	}

	return nil
}

func (s *LumberjackSink) Close() error {
	return s.File.Close()
}

type Config struct {
	Level      string
	LogFile    string
	MaxSize    int
	MaxAge     int
	MaxBackups int
	Encoding   string
}

var defaultConfig = Config{
	Level:      "info",
	LogFile:    "",
	MaxSize:    100,
	MaxAge:     30,
	MaxBackups: 10,
	Encoding:   "json",
}

func Configure(cfg Config) error {
	defaultConfig = cfg
	return nil
}

func (c *Config) Apply() *Logger {
	var writer io.Writer = os.Stderr

	if c.LogFile != "" {
		sink, err := NewLumberjackSink(c.LogFile, c.MaxSize, c.MaxAge, c.MaxBackups)
		if err == nil {
			writer = sink
		}
	}

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var encoder zapcore.Encoder
	if c.Encoding == "console" {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	level := zapcore.InfoLevel
	switch c.Level {
	case "debug":
		level = zapcore.DebugLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	}

	core := zapcore.NewCore(encoder, zapcore.AddSync(writer), level)
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	defaultLogger = &Logger{Logger: logger}
	return defaultLogger
}

func NewProductionLogger() *Logger {
	cfg := Config{
		Level:    "info",
		Encoding: "json",
	}
	return cfg.Apply()
}

func NewDevelopmentLogger() *Logger {
	cfg := Config{
		Level:    "debug",
		Encoding: "console",
	}
	return cfg.Apply()
}

func (l *Logger) Sync() error {
	return l.Logger.Sync()
}

type Field = zap.Field

func (l *Logger) Debug(msg string, fields ...Field) {
	l.Logger.Debug(msg, fields...)
}

func (l *Logger) Info(msg string, fields ...Field) {
	l.Logger.Info(msg, fields...)
}

func (l *Logger) Warn(msg string, fields ...Field) {
	l.Logger.Warn(msg, fields...)
}

func (l *Logger) Error(msg string, fields ...Field) {
	l.Logger.Error(msg, fields...)
}

func (l *Logger) Fatal(msg string, fields ...Field) {
	l.Logger.Fatal(msg, fields...)
}

func String(key, val string) Field {
	return zap.String(key, val)
}

func Int(key string, val int) Field {
	return zap.Int(key, val)
}

func Int64(key string, val int64) Field {
	return zap.Int64(key, val)
}

func Float64(key string, val float64) Field {
	return zap.Float64(key, val)
}

func Bool(key string, val bool) Field {
	return zap.Bool(key, val)
}

func Err(err error) Field {
	return zap.Error(err)
}

func Duration(key string, val time.Duration) Field {
	return zap.Duration(key, val)
}

func Time(key string, val time.Time) Field {
	return zap.Time(key, val)
}

func Strings(key string, val []string) Field {
	return zap.Strings(key, val)
}

func Int64s(key string, val []int64) Field {
	return zap.Int64s(key, val)
}

func Object(key string, val zapcore.ObjectMarshaler) Field {
	return zap.Object(key, val)
}

func Any(key string, val interface{}) Field {
	return zap.Any(key, val)
}
