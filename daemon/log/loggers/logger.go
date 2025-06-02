package loggers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
)

const logTag = "opensnitch"

// Logger is the common interface that every logger must met.
// Serves as a generic holder of different types of loggers.
type Logger interface {
	Transform(...interface{}) string
	Write(string)
	Close() error
}

// LoggerConfig holds the configuration of a logger
type LoggerConfig struct {
	// Name of the logger: syslog, elastic, ...
	Name string

	// Format: rfc5424, csv, json, ...
	Format string

	// Protocol: udp, tcp
	Protocol string

	// Server: 127.0.0.1:514
	Server string

	// WriteTimeout ...
	WriteTimeout string

	// ConnectTimeout ...
	ConnectTimeout string

	// Tag: opensnitchd, mytag, ...
	Tag string

	// Workers: number of workers
	Workers int

	// MaxConnectAttempts holds the max attemps to connect to the remote server.
	// A value of 0 will try to connect indefinitely.
	MaxConnectAttempts uint16
}

// LoggerManager represents the LoggerManager.
type LoggerManager struct {
	ctx           context.Context
	cancel        context.CancelFunc
	configs       []LoggerConfig
	loggers       map[string]Logger
	msgs          chan []interface{}
	count         int
	workers       int
	queueFullHits int
	mu            *sync.RWMutex
}

// NewLoggerManager instantiates all the configured loggers.
func NewLoggerManager() *LoggerManager {
	ctx, cancel := context.WithCancel(context.Background())
	lm := &LoggerManager{
		mu:      &sync.RWMutex{},
		ctx:     ctx,
		cancel:  cancel,
		loggers: make(map[string]Logger),
	}

	return lm
}

// Load loggers configuration and initialize them.
func (l *LoggerManager) Load(configs []LoggerConfig) {
	l.ctx, l.cancel = context.WithCancel(context.Background())

	l.mu.Lock()
	defer l.mu.Unlock()
	l.configs = configs

	for _, cfg := range configs {
		switch cfg.Name {
		case LOGGER_REMOTE, LOGGER_REMOTE_SYSLOG, LOGGER_SYSLOG:
			l.workers += cfg.Workers
			l.count++
		}
	}
	if l.count == 0 {
		return
	}
	if l.workers == 0 {
		l.workers = 4
	}

	// TODO: allow to configure messages queue size
	l.msgs = make(chan []interface{}, l.workers)
	for i := 0; i < l.workers; i++ {
		go newWorker(i, l.ctx.Done(), l.msgs, l.write)
	}

	for _, cfg := range configs {
		switch cfg.Name {
		case LOGGER_REMOTE:
			lgr, _ := NewRemote(cfg)
			l.loggers[fmt.Sprint(lgr.Name, lgr.cfg.Server, lgr.cfg.Protocol)] = lgr
		case LOGGER_REMOTE_SYSLOG:
			lgr, _ := NewRemoteSyslog(cfg)
			l.loggers[fmt.Sprint(lgr.Name, lgr.cfg.Server, lgr.cfg.Protocol)] = lgr
		case LOGGER_SYSLOG:
			lgr, _ := NewSyslog(cfg)
			l.loggers[lgr.Name] = lgr
		}
	}

}

// Reload stops and loads the configured loggers again
func (l *LoggerManager) Reload() {
	l.Stop()
	l.Load(l.configs)
}

// Stop closes the opened loggers, and closes the workers
func (l *LoggerManager) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.count = 0
	l.workers = 0
	l.queueFullHits = 0

	l.cancel()
	for _, lg := range l.loggers {
		lg.Close()
	}
	l.loggers = make(map[string]Logger)
}

func (l *LoggerManager) write(args ...interface{}) {
	//l.mu.RLock()
	//defer l.mu.RUnlock()
	// FIXME: leak when configuring the loggers.
	for _, logger := range l.loggers {
		logger.Write(logger.Transform(args...))
	}
}

func newWorker(id int, done <-chan struct{}, msgs chan []interface{}, write func(args ...interface{})) {
	for {
		select {
		case <-done:
			goto Exit
		case msg := <-msgs:
			write(msg)
		}
	}
Exit:
	log.Debug("logger worker %d exited", id)
}

// Log sends data to the loggers.
func (l *LoggerManager) Log(args ...interface{}) {
	if l.count == 0 {
		return
	}

	// Sending messages to the queue (channel) should be instantaneous, but there're
	// several scenarios where we can end up filling up the queue (channel):
	// - If we're not connected to the server (GUI), and we need to allow some
	//   connections.
	// - If there's a high load, all workers busy, and writing the logs to the
	//   logger take too much time.
	// In these and other scenarios, if we try to send more than <queueFullHits> times
	// while the queue (channel) is full, we'll reload the loggers.
	select {
	case <-time.After(time.Millisecond * 1):
		l.mu.Lock()
		log.Debug("loggerMgr.Log() TIMEOUT dispatching log, queued: %d, queue full hits: %d", len(l.msgs), l.queueFullHits)
		l.queueFullHits++
		// TODO: make queueFullHits configurable
		needsReload := len(l.msgs) == l.workers && l.queueFullHits > 30
		l.mu.Unlock()

		if needsReload {
			// FIXME: races occurs on l.write() and l.Load()
			l.Reload()
		}
	case l.msgs <- args:
	}
}
