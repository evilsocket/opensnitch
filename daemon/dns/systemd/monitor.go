// Package systemd defines several utilities to interact with systemd.
//
// ResolvedMonitor:
//  * To debug systemd-resolved queries and inspect the protocol:
//    - resolvectl monitor
//  * Resources:
//   - https://github.com/systemd/systemd/blob/main/src/resolve/resolvectl.c
//   - The protocol used to send and receive data is varlink:
//     https://github.com/varlink/go
//     https://github.com/systemd/systemd/blob/main/src/resolve/resolved-varlink.c
//   - https://systemd.io/RESOLVED-VPNS/
package systemd

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/evilsocket/opensnitch/daemon/log"

	"github.com/varlink/go/varlink"
)

// whenever there's a new DNS response, this callback will be invoked.
// the second parameter is a MonitorResponse struct that will be filled with
// data.
type resolvedCallback func(context.Context, interface{}) (uint64, error)

const (
	// SuccessState is the string returned by systemd-resolved when a DNS query is successful.
	// Other states: https://github.com/systemd/systemd/blob/main/src/resolve/resolved-dns-transaction.c#L3608
	SuccessState = "success"

	socketPath              = "/run/systemd/resolve/io.systemd.Resolve.Monitor"
	resolvedSubscribeMethod = "io.systemd.Resolve.Monitor.SubscribeQueryResults"

	// DNSTypeA A
	DNSTypeA = 1
	// DNSTypeAAAA AAAA
	DNSTypeAAAA = 28
	// DNSTypeCNAME cname
	DNSTypeCNAME = 5
	// DNSTypeSOA soa
	DNSTypeSOA = 6
)

// QuestionMonitorResponse represents a DNS query
//  "question": [{"class": 1, "type": 28,"name": "images.site.com"}],
type QuestionMonitorResponse struct {
	Name  string `json:"name"`
	Class int    `json:"class"`
	Type  int    `json:"type"`
}

// KeyType holds question that generated the answer
/*answer: [{
	"rr": {
		"key": {
			"class": 1,
			"type": 28,
			"name": "images.site.com"
		},
		"address": [100, 13, 45, 111]
	},
	"raw": "DFJFKE343443EFKEREKET=",
	"ifindex": 3
}]*/
type KeyType struct {
	Name  string `json:"name"`
	Class int    `json:"class"`
	Type  int    `json:"type"`
}

// RRType represents a DNS answer
// if the response is a CNAME, Address will be nil, and Name a domain name.
type RRType struct {
	Name    string                  `json:"name"`
	Address []byte                  `json:"address"`
	Key     QuestionMonitorResponse `json:"key"`
}

// AnswerMonitorResponse represents the DNS answer of a DNS query.
type AnswerMonitorResponse struct {
	Raw     string `json:"raw"`
	RR      RRType `json:"rr"`
	Ifindex int    `json:"ifindex"`
}

// MonitorResponse represents the systemd-resolved protocol message
// sent over the wire, that holds the answer to a DNS query.
type MonitorResponse struct {
	State    string                    `json:"state"`
	Question []QuestionMonitorResponse `json:"question"`
	// CollectedQuestions
	// "collectedQuestions":[{"class":1,"type":1,"name":"translate.google.com"}]
	Answer    []AnswerMonitorResponse `json:"answer"`
	Continues bool                    `json:"continues"`
}

// ResolvedMonitor represents a systemd-resolved monitor
type ResolvedMonitor struct {
	Ctx    context.Context
	Cancel context.CancelFunc

	// connection with the systemd-resolved unix socket:
	// /run/systemd/resolve/io.systemd.Resolve.Monitor
	Conn *varlink.Connection
	// channel where all the DNS respones will be sent
	ChanResponse chan *MonitorResponse

	// error channel to signal any problem
	ChanConnError chan error

	// callback that is emited when systemd-resolved resolves a domain name.
	receiverCb resolvedCallback
	mu         *sync.RWMutex
	connected  bool
}

// NewResolvedMonitor returns a new ResolvedMonitor object.
// With this object you can passively read DNS answers.
func NewResolvedMonitor() (*ResolvedMonitor, error) {
	if core.Exists(socketPath) == false {
		return nil, fmt.Errorf("%s doesn't exist", socketPath)
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &ResolvedMonitor{
		mu:            &sync.RWMutex{},
		Ctx:           ctx,
		Cancel:        cancel,
		ChanResponse:  make(chan *MonitorResponse),
		ChanConnError: make(chan error),
	}, nil
}

// Connect opens a unix socket with systemd-resolved
func (r *ResolvedMonitor) Connect() (*varlink.Connection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var err error
	r.Conn, err = varlink.NewConnection(r.Ctx, fmt.Sprintf("unix://%s", socketPath))
	if err != nil {
		return nil, err
	}

	r.connected = true
	go r.connPoller()
	return r.Conn, nil
}

// if we're connected to the unix socket, check every few seconds if we're still
// connected, and if not, reconnect, to survive to systemd-resolved restarts.
func (r *ResolvedMonitor) connPoller() {
	for {
		select {
		case <-time.After(5 * time.Second):
			if r.isConnected() {
				continue
			}
			log.Debug("ResolvedMonitor not connected")
			if _, err := r.Connect(); err == nil {
				r.Subscribe()
			}
			goto Exit
		}
	}
Exit:
	log.Debug("ResolvedMonitor connection poller exit.")
}

// Subscribe sends the instruction to systemd-resolved to start monitoring
// DNS answers.
func (r *ResolvedMonitor) Subscribe() error {
	if r.isConnected() == false {
		return errors.New("Not connected")
	}
	var err error
	type emptyT struct{}
	empty := &emptyT{}
	r.receiverCb, err = r.Conn.Send(r.Ctx, resolvedSubscribeMethod, empty, varlink.Continues|varlink.More)
	if err != nil {
		return err
	}
	go r.monitor(r.Ctx, r.ChanResponse, r.ChanConnError, r.receiverCb)

	return nil
}

// monitor will listen for DNS answers from systemd-resolved.
func (r *ResolvedMonitor) monitor(ctx context.Context, chanResponse chan *MonitorResponse, chanConnError chan error, callback resolvedCallback) {
	for {
		m := &MonitorResponse{}
		continues, err := callback(ctx, m)
		if err != nil {
			chanConnError <- err
			goto Exit
		}
		if continues != varlink.Continues {
			goto Exit
		}
		log.Debug("ResolvedMonitor >> new response: %#v", m)
		chanResponse <- m
	}

Exit:
	r.mu.Lock()
	r.connected = false
	r.mu.Unlock()
	log.Debug("ResolvedMonitor.monitor() exit.")
}

// GetDNSResponses returns a channel that you can use to read responses.
func (r *ResolvedMonitor) GetDNSResponses() chan *MonitorResponse {
	return r.ChanResponse
}

// Exit returns a channel to listen for connection errors.
func (r *ResolvedMonitor) Exit() chan error {
	return r.ChanConnError
}

// Close closes the unix socket with systemd-resolved
func (r *ResolvedMonitor) Close() {
	r.ChanConnError <- nil
	r.Cancel()
}

func (r *ResolvedMonitor) isConnected() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.connected
}
