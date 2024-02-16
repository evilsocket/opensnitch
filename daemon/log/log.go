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

// log level constants
const (
	DEBUG = iota
	INFO
	IMPORTANT
	WARNING
	ERROR
	FATAL
)

//
var (
	WithColors = true
	Output     = os.Stdout
	StdoutFile = "/dev/stdout"
	DateFormat = "2006-01-02 15:04:05"
	MinLevel   = INFO
	LogUTC     = true
	LogMicro   = false

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

// Wrap wraps a text with effects
func Wrap(s, effect string) string {
	if WithColors == true {
		s = effect + s + RESET
	}
	return s
}

// Dim dims a text
func Dim(s string) string {
	return Wrap(s, DIM)
}

// Bold bolds a text
func Bold(s string) string {
	return Wrap(s, BOLD)
}

// Red reds the text
func Red(s string) string {
	return Wrap(s, RED)
}

// Green greens the text
func Green(s string) string {
	return Wrap(s, GREEN)
}

// Blue blues the text
func Blue(s string) string {
	return Wrap(s, BLUE)
}

// Yellow yellows the text
func Yellow(s string) string {
	return Wrap(s, YELLOW)
}

// Raw prints out a text without colors
func Raw(format string, args ...interface{}) {
	mutex.RLock()
	defer mutex.RUnlock()
	fmt.Fprintf(Output, format, args...)
}

// SetLogLevel sets the log level
func SetLogLevel(newLevel int) {
	mutex.Lock()
	defer mutex.Unlock()
	MinLevel = newLevel
}

// GetLogLevel returns the current log level configured.
func GetLogLevel() int {
	mutex.RLock()
	defer mutex.RUnlock()

	return MinLevel
}

// SetLogUTC configures UTC timestamps
func SetLogUTC(newLogUTC bool) {
	mutex.Lock()
	defer mutex.Unlock()
	LogUTC = newLogUTC
}

// GetLogUTC returns the current config.
func GetLogUTC() bool {
	mutex.RLock()
	defer mutex.RUnlock()

	return LogUTC
}

// SetLogMicro configures microsecond timestamps
func SetLogMicro(newLogMicro bool) {
	mutex.Lock()
	defer mutex.Unlock()
	LogMicro = newLogMicro
}

// GetLogMicro returns the current config.
func GetLogMicro() bool {
	mutex.Lock()
	defer mutex.Unlock()

	return LogMicro
}

// Log prints out a text with the given color and format
func Log(level int, format string, args ...interface{}) {
	mutex.Lock()
	defer mutex.Unlock()
	if level >= MinLevel {
		label := labels[level]
		color := colors[level]

		datefmt := DateFormat

		if LogMicro == true {
			datefmt = DateFormat + ".000000"
		}
		when := time.Now().UTC().Format(datefmt)
		if LogUTC == false {
			when = time.Now().Local().Format(datefmt)
		}

		what := fmt.Sprintf(format, args...)
		if strings.HasSuffix(what, "\n") == false {
			what += "\n"
		}

		l := Dim("[%s]")
		r := Wrap(" %s ", color) + " %s"

		fmt.Fprintf(Output, l+" "+r, when, label, what)
	}
}

func setDefaultLogOutput() {
	mutex.Lock()
	Output = os.Stdout
	mutex.Unlock()
}

// OpenFile opens a file to print out the logs
func OpenFile(logFile string) (err error) {
	if logFile == StdoutFile {
		setDefaultLogOutput()
		return
	}

	if Output, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err != nil {
		Error("Error opening log: %s %s", logFile, err)
		//fallback to stdout
		setDefaultLogOutput()
	}
	Important("Start writing logs to %s", logFile)

	return err
}

// Close closes the current output file descriptor
func Close() {
	if Output != os.Stdout {
		Output.Close()
	}
}

// Debug is the log level for debugging purposes
func Debug(format string, args ...interface{}) {
	Log(DEBUG, format, args...)
}

// Info is the log level for informative messages
func Info(format string, args ...interface{}) {
	Log(INFO, format, args...)
}

// Important is the log level for things that must pay attention
func Important(format string, args ...interface{}) {
	Log(IMPORTANT, format, args...)
}

// Warning is the log level for non-critical errors
func Warning(format string, args ...interface{}) {
	Log(WARNING, format, args...)
}

// Error is the log level for errors that should be corrected
func Error(format string, args ...interface{}) {
	Log(ERROR, format, args...)
}

// Fatal is the log level for errors that must be corrected before continue
func Fatal(format string, args ...interface{}) {
	Log(FATAL, format, args...)
	os.Exit(1)
}
