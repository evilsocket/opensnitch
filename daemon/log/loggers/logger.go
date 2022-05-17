package loggers

// Logger is the common interface that every logger must met.
// Serves as a generic holder of different types of loggers.
type Logger interface {
	Transform(...interface{}) string
	Write(string)
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
	// Tag: opensnitchd, mytag, ...
	Tag string
}

// LoggerManager represents the LoggerManager.
type LoggerManager struct {
	loggers map[string]Logger
	msgs    chan []interface{}
	count   int
}

// NewLoggerManager instantiates all the configured loggers.
func NewLoggerManager() *LoggerManager {
	lm := &LoggerManager{
		loggers: make(map[string]Logger),
		msgs:    make(chan []interface{}),
	}

	return lm
}

// Load loggers configuration and initialize them.
func (l *LoggerManager) Load(configs []LoggerConfig, workers int) {
	for _, cfg := range configs {
		switch cfg.Name {
		case LOGGER_SYSLOG:
			l.count++
			if lgr, err := NewSyslog(&cfg); err == nil {
				l.loggers[lgr.Name] = lgr
			}
		}
	}

	if workers == 0 {
		workers = 4
	}

	for i := 0; i < workers; i++ {
		go newWorker(i, l)
	}

}

func (l *LoggerManager) write(args ...interface{}) {
	for _, logger := range l.loggers {
		logger.Write(logger.Transform(args...))
	}
}

func newWorker(id int, lgmr *LoggerManager) {
	var c int
	for {
		select {
		case msg := <-lgmr.msgs:
			c++
			lgmr.write(msg)
		}
	}
}

// Log sends data to the loggers.
func (l *LoggerManager) Log(args ...interface{}) {
	if l.count > 0 {
		l.msgs <- args
	}
}
