// logger.go - Structured logging for the auction protocol
package main

import (
	"fmt"
	"log"
	"os"
	"time"
)

// LogLevel represents the logging level
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

// Logger represents a structured logger
type Logger struct {
	level    LogLevel
	file     *os.File
	fileLog  *log.Logger
	console  *log.Logger
	auditLog *log.Logger
}

// NewLogger creates a new logger instance
func NewLogger(level string, logFile string, auditFile string) (*Logger, error) {
	// Parse log level
	var logLevel LogLevel
	switch level {
	case "debug":
		logLevel = DEBUG
	case "info":
		logLevel = INFO
	case "warn":
		logLevel = WARN
	case "error":
		logLevel = ERROR
	case "fatal":
		logLevel = FATAL
	default:
		logLevel = INFO
	}

	// Create logger
	logger := &Logger{
		level:   logLevel,
		console: log.New(os.Stdout, "", log.LstdFlags),
	}

	// Setup file logging if specified
	if logFile != "" {
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		logger.file = file
		logger.fileLog = log.New(file, "", log.LstdFlags)
	}

	// Setup audit logging if specified
	if auditFile != "" {
		auditFile, err := os.OpenFile(auditFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit file: %w", err)
		}
		logger.auditLog = log.New(auditFile, "", log.LstdFlags)
	}

	return logger, nil
}

// Close closes the logger and its files
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// log writes a log message with the given level
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	levelStr := "INFO"
	switch level {
	case DEBUG:
		levelStr = "DEBUG"
	case INFO:
		levelStr = "INFO"
	case WARN:
		levelStr = "WARN"
	case ERROR:
		levelStr = "ERROR"
	case FATAL:
		levelStr = "FATAL"
	}

	message := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s: %s", timestamp, levelStr, message)

	// Console output
	l.console.Print(logEntry)

	// File output
	if l.fileLog != nil {
		l.fileLog.Print(logEntry)
	}

	// Audit log for important events
	if l.auditLog != nil && (level >= WARN) {
		l.auditLog.Print(logEntry)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(FATAL, format, args...)
	os.Exit(1)
}

// Audit logs an audit event
func (l *Logger) Audit(event string, details map[string]interface{}) {
	if l.auditLog != nil {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		auditEntry := fmt.Sprintf("[%s] AUDIT: %s - %+v", timestamp, event, details)
		l.auditLog.Print(auditEntry)
	}
}
