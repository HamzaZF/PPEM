package logger

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Level int

const (
	LevelQuiet Level = iota
	LevelInfo
	LevelDebug
	LevelTrace
)

type Logger struct {
	level    Level
	start    time.Time
	useColor bool
}

var global *Logger

func Setup(levelStr string) {
	lvl := LevelInfo
	switch strings.ToLower(levelStr) {
	case "quiet":
		lvl = LevelQuiet
	case "debug":
		lvl = LevelDebug
	case "trace":
		lvl = LevelTrace
	default:
		lvl = LevelInfo
	}
	global = &Logger{level: lvl, start: time.Now(), useColor: isTTY()}
}

func isTTY() bool {
	// Simple heuristic; could integrate isatty if needed
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func nowTs() string { return fmt.Sprintf("[%05.3f]", time.Since(global.start).Seconds()) }

func color(code string) string {
	if global == nil || !global.useColor {
		return ""
	}
	return code
}

var (
	cReset = "\x1b[0m"
	cBold  = "\x1b[1m"
	cBlue  = "\x1b[34m"
	cCyan  = "\x1b[36m"
	cGreen = "\x1b[32m"
	cGray  = "\x1b[90m"
)

func Header(title string, subtitle string) {
	if global == nil || global.level == LevelQuiet {
		return
	}
	bar := color(cBold+cCyan) + "┌" + strings.Repeat("─", len(title)+2) + "┐" + color(cReset)
	fmt.Println(bar)
	fmt.Println(color(cBold+cCyan) + "│ " + title + " │" + color(cReset))
	fmt.Println(color(cBold+cCyan) + "└" + strings.Repeat("─", len(title)+2) + "┘" + color(cReset))
	if subtitle != "" {
		fmt.Println(color(cGray) + subtitle + color(cReset))
	}
}

func Phase(name string) {
	if global == nil || global.level == LevelQuiet {
		return
	}
	fmt.Println(color(cBold+cBlue) + "── " + name + " " + strings.Repeat("─", 74-len(name)) + color(cReset))
}

func StepOk(name, detail string, dur time.Duration) {
	if global == nil || global.level == LevelQuiet {
		return
	}
	check := color(cGreen) + "✔" + color(cReset)
	if detail != "" {
		fmt.Printf("%s %s %-14s %s %s\n", check, name, color(cGray)+detail+color(cReset), color(cGray), fmt.Sprintf("(%s)", durString(dur))+color(cReset))
	} else {
		fmt.Printf("%s %s %s\n", check, name, color(cGray)+fmt.Sprintf("(%s)", durString(dur))+color(cReset))
	}
}

func Infof(format string, args ...any) {
	if global == nil || global.level < LevelInfo {
		return
	}
	fmt.Printf(format, args...)
}
func Debugf(format string, args ...any) {
	if global == nil || global.level < LevelDebug {
		return
	}
	fmt.Printf("%s ", nowTs())
	fmt.Printf(format, args...)
}
func Tracef(format string, args ...any) {
	if global == nil || global.level < LevelTrace {
		return
	}
	fmt.Printf("%s ", nowTs())
	fmt.Printf(format, args...)
}

func Fatalf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
	os.Exit(1)
}

func EnabledTrace() bool { return global != nil && global.level >= LevelTrace }
func EnabledDebug() bool { return global != nil && global.level >= LevelDebug }

func durString(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
