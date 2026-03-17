// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

type Logger struct {
	name  string
	level int
	base  *log.Logger
	color bool
}

const (
	levelDebug = iota
	levelInfo
	levelWarn
	levelError
)

var colorTagCodes = map[string]string{
	"<black>":    "\x1b[30m",
	"<red>":      "\x1b[31m",
	"<green>":    "\x1b[32m",
	"<yellow>":   "\x1b[33m",
	"<blue>":     "\x1b[34m",
	"<magenta>":  "\x1b[35m",
	"<cyan>":     "\x1b[36m",
	"<white>":    "\x1b[37m",
	"<gray>":     "\x1b[90m",
	"<grey>":     "\x1b[90m",
	"<bold>":     "\x1b[1m",
	"<reset>":    "\x1b[0m",
	"</black>":   "\x1b[0m",
	"</red>":     "\x1b[0m",
	"</green>":   "\x1b[0m",
	"</yellow>":  "\x1b[0m",
	"</blue>":    "\x1b[0m",
	"</magenta>": "\x1b[0m",
	"</cyan>":    "\x1b[0m",
	"</white>":   "\x1b[0m",
	"</gray>":    "\x1b[0m",
	"</grey>":    "\x1b[0m",
	"</bold>":    "\x1b[0m",
}

func New(name, rawLevel string) *Logger {
	return &Logger{
		name:  name,
		level: parseLevel(rawLevel),
		base:  log.New(os.Stdout, "", log.LstdFlags),
		color: shouldUseColor(),
	}
}

func parseLevel(raw string) int {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "DEBUG":
		return levelDebug
	case "WARNING", "WARN":
		return levelWarn
	case "ERROR", "CRITICAL":
		return levelError
	default:
		return levelInfo
	}
}

func (l *Logger) logf(level int, levelName string, format string, args ...any) {
	if l == nil || level < l.level {
		return
	}
	msg := format
	if len(args) != 0 {
		msg = fmt.Sprintf(format, args...)
	}
	appName := "[" + l.name + "]"
	levelText := "[" + levelName + "]"

	if l.color {
		if strings.IndexByte(msg, '<') >= 0 {
			msg = renderColorTags(msg)
		}
		appName = "\x1b[36m" + appName + "\x1b[0m"
		levelText = colorizeLevel(level, levelText)
	}

	l.base.Printf("%s %s %s", appName, levelText, msg)
}

func (l *Logger) Debugf(format string, args ...any) { l.logf(levelDebug, "DEBUG", format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.logf(levelInfo, "INFO", format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.logf(levelWarn, "WARN", format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.logf(levelError, "ERROR", format, args...) }

func shouldUseColor() bool {
	if strings.TrimSpace(os.Getenv("NO_COLOR")) != "" {
		return false
	}
	if strings.TrimSpace(os.Getenv("FORCE_COLOR")) != "" {
		return true
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func colorizeLevel(level int, text string) string {
	switch level {
	case levelDebug:
		return "\x1b[35m" + text + "\x1b[0m"
	case levelInfo:
		return "\x1b[32m" + text + "\x1b[0m"
	case levelWarn:
		return "\x1b[33m" + text + "\x1b[0m"
	case levelError:
		return "\x1b[31m" + text + "\x1b[0m"
	default:
		return text
	}
}

func renderColorTags(text string) string {
	start := strings.IndexByte(text, '<')
	if start == -1 {
		return text
	}

	var b strings.Builder
	b.Grow(len(text) + 16)
	b.WriteString(text[:start])

	for i := start; i < len(text); {
		if text[i] != '<' {
			next := strings.IndexByte(text[i:], '<')
			if next == -1 {
				b.WriteString(text[i:])
				break
			}
			b.WriteString(text[i : i+next])
			i += next
			continue
		}

		end := strings.IndexByte(text[i:], '>')
		if end == -1 {
			b.WriteString(text[i:])
			break
		}

		tag := strings.ToLower(text[i : i+end+1])
		if code, ok := colorTagCodes[tag]; ok {
			b.WriteString(code)
		} else {
			b.WriteString(text[i : i+end+1])
		}
		i += end + 1
	}

	return b.String()
}

func NowUnixNano() int64 {
	return time.Now().UnixNano()
}
