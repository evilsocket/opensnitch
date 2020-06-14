package log

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Handler func(format string, args ...interface{})

// https://misc.flogisoft.com/bash/tip_colors_and_formatting
const (
	BOLD = "\033[1m"
	DIM  = "\033[2m"

	RED    = "\033[31m"
	GREEN  = "\033[32m"
	BLUE   = "\033[34m"
	YELLOW = "\033[33m"

	FG_BLACK = "\033[30m"
	FG_WHITE = "\033[97m"

	BG_DGRAY  = "\033[100m"
	BG_RED    = "\033[41m"
	BG_GREEN  = "\033[42m"
	BG_YELLOW = "\033[43m"
	BG_LBLUE  = "\033[104m"

	RESET = "\033[0m"
)

const (
	DEBUG = iota
	INFO
	IMPORTANT
	WARNING
	ERROR
	FATAL
)

var (
	WithColors = true
	Output     = os.Stdout
	DateFormat = "2006-01-02 15:04:05"
	MinLevel   = INFO

	mutex  = &sync.RWMutex{}
	labels = map[int]string{
		DEBUG:     "DBG",
		INFO:      "INF",
		IMPORTANT: "IMP",
		WARNING:   "WAR",
		ERROR:     "ERR",
		FATAL:     "!!!",
	}
	colors = map[int]string{
		DEBUG:     DIM + FG_BLACK + BG_DGRAY,
		INFO:      FG_WHITE + BG_GREEN,
		IMPORTANT: FG_WHITE + BG_LBLUE,
		WARNING:   FG_WHITE + BG_YELLOW,
		ERROR:     FG_WHITE + BG_RED,
		FATAL:     FG_WHITE + BG_RED + BOLD,
	}
)

func Wrap(s, effect string) string {
	if WithColors == true {
		s = effect + s + RESET
	}
	return s
}

func Dim(s string) string {
	return Wrap(s, DIM)
}

func Bold(s string) string {
	return Wrap(s, BOLD)
}

func Red(s string) string {
	return Wrap(s, RED)
}

func Green(s string) string {
	return Wrap(s, GREEN)
}

func Blue(s string) string {
	return Wrap(s, BLUE)
}

func Yellow(s string) string {
	return Wrap(s, YELLOW)
}

func Raw(format string, args ...interface{}) {
	mutex.Lock()
	defer mutex.Unlock()
	fmt.Fprintf(Output, format, args...)
}

func SetLogLevel(newLevel int) {
	mutex.RLock()
	defer mutex.RUnlock()
	MinLevel = newLevel
}

func Log(level int, format string, args ...interface{}) {
	mutex.Lock()
	defer mutex.Unlock()
	if level >= MinLevel {
		label := labels[level]
		color := colors[level]
		when := time.Now().UTC().Format(DateFormat)

		what := fmt.Sprintf(format, args...)
		if strings.HasSuffix(what, "\n") == false {
			what += "\n"
		}

		l := Dim("[%s]")
		r := Wrap(" %s ", color) + " %s"

		fmt.Fprintf(Output, l+" "+r, when, label, what)
	}
}

func Debug(format string, args ...interface{}) {
	Log(DEBUG, format, args...)
}

func Info(format string, args ...interface{}) {
	Log(INFO, format, args...)
}

func Important(format string, args ...interface{}) {
	Log(IMPORTANT, format, args...)
}

func Warning(format string, args ...interface{}) {
	Log(WARNING, format, args...)
}

func Error(format string, args ...interface{}) {
	Log(ERROR, format, args...)
}

func Fatal(format string, args ...interface{}) {
	Log(FATAL, format, args...)
	os.Exit(1)
}
