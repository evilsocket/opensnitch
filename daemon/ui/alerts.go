package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/evilsocket/opensnitch/daemon/conman"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/ui/protocol"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"
)

// NewWarningAlert builts a new warning alert
func NewWarningAlert(what protocol.Alert_What, data interface{}) *protocol.Alert {
	return NewAlert(protocol.Alert_WARNING, what, protocol.Alert_SHOW_ALERT, protocol.Alert_MEDIUM, data)
}

// NewErrorAlert builts a new error alert
func NewErrorAlert(what protocol.Alert_What, data interface{}) *protocol.Alert {
	return NewAlert(protocol.Alert_ERROR, what, protocol.Alert_SHOW_ALERT, protocol.Alert_HIGH, data)
}

// NewAlert builts a new generic alert
func NewAlert(atype protocol.Alert_Type, what protocol.Alert_What, action protocol.Alert_Action, prio protocol.Alert_Priority, data interface{}) *protocol.Alert {
	a := &protocol.Alert{
		Id:       uint64(time.Now().UnixNano()),
		Type:     atype,
		Action:   action,
		What:     what,
		Priority: prio,
	}

	switch what {
	case protocol.Alert_KERNEL_EVENT:

		switch data.(type) {
		case procmon.Process:
			a.Data = &protocol.Alert_Proc{
				data.(*procmon.Process).Serialize(),
			}
		case string:
			a.Data = &protocol.Alert_Text{data.(string)}
			a.Action = protocol.Alert_SHOW_ALERT
		}
	case protocol.Alert_CONNECTION:
		a.Data = &protocol.Alert_Conn{
			data.(*conman.Connection).Serialize(),
		}
	case protocol.Alert_GENERIC:
		a.Data = &protocol.Alert_Text{data.(string)}
	case protocol.Alert_PORT_SCAN:
		switch v := data.(type) {
		case *protocol.PortScan:
			a.Portscan = v
			a.Data = &protocol.Alert_Text{Text: portScanSummary(v, prio == protocol.Alert_HIGH)}
		case string:
			a.Data = &protocol.Alert_Text{Text: v}
		}
	}

	return a
}

// portScanSummary is the text a GUI that does not know the PortScan message
// shows instead of it: an older GUI connected to a newer daemon, which is an
// ordinary combination (a GUI installed with pip, or one GUI watching several
// nodes). It names what the event names, and says why no block can be chosen.
func portScanSummary(p *protocol.PortScan, proposed bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Inbound port scan from %s", p.SrcIp)
	if p.Interface != "" {
		fmt.Fprintf(&b, " on %s", p.Interface)
	}
	if p.Method != "" {
		fmt.Fprintf(&b, ": %s", p.Method)
	}
	switch {
	case p.IsProtocolScan:
		fmt.Fprintf(&b, ", %d IP protocols", p.Protocols)
	case p.DistinctPorts > 0:
		fmt.Fprintf(&b, ", %d ports between %d and %d", p.DistinctPorts, p.MinPort, p.MaxPort)
	}
	b.WriteString(".")
	if proposed {
		b.WriteString(" Blocking this source can be decided from a GUI that supports port scan detection.")
	}
	return b.String()
}

// SendPortScanAlert reports an inbound port scan to the GUI.
//
// The priority is not derived from how alarming the scan looks but from
// whether the user has something to decide: an alert proposing a block needs
// an answer, one merely recording a detection does not. Marking every scan
// critical would train the user to dismiss them, which is how a real one gets
// missed.
func (c *Client) SendPortScanAlert(scan *protocol.PortScan, needsAnswer bool) {
	prio := protocol.Alert_MEDIUM
	if needsAnswer {
		prio = protocol.Alert_HIGH
	}
	c.PostAlert(
		protocol.Alert_WARNING,
		protocol.Alert_PORT_SCAN,
		protocol.Alert_SHOW_ALERT,
		prio,
		scan,
	)
}

// SendInfoAlert sends an info alert
func (c *Client) SendInfoAlert(data interface{}) {
	c.PostAlert(protocol.Alert_INFO, protocol.Alert_GENERIC, protocol.Alert_SHOW_ALERT, protocol.Alert_LOW, data)
}

// SendWarningAlert sends an warning alert
func (c *Client) SendWarningAlert(data interface{}) {
	c.PostAlert(protocol.Alert_WARNING, protocol.Alert_GENERIC, protocol.Alert_SHOW_ALERT, protocol.Alert_MEDIUM, data)
}

// SendErrorAlert sends an error alert
func (c *Client) SendErrorAlert(data interface{}) {
	c.PostAlert(protocol.Alert_ERROR, protocol.Alert_GENERIC, protocol.Alert_SHOW_ALERT, protocol.Alert_HIGH, data)
}

// alertsDispatcher waits to be connected to the GUI.
// Once connected, dispatches all the queued alerts.
func (c *Client) alertsDispatcher() {
	queuedAlerts := make(chan protocol.Alert, 32)
	connected := false

	isQueueFull := func(qdAlerts chan protocol.Alert) bool { return len(qdAlerts) > 31 }
	isQueueEmpty := func(qdAlerts chan protocol.Alert) bool { return len(qdAlerts) == 0 }
	queueAlert := func(qdAlerts chan protocol.Alert, pbAlert protocol.Alert) {
		if isQueueFull(qdAlerts) {
			v := <-qdAlerts
			// empty queue before adding a new one
			log.Debug("Discarding queued alert (%d): %v", len(qdAlerts), v)
		}
		select {
		case qdAlerts <- pbAlert:
		default:
			log.Debug("Alert not sent to queue, full? (%d)", len(qdAlerts))
		}
	}

	for {
		select {
		case pbAlert := <-c.alertsChan:
			if !connected {
				queueAlert(queuedAlerts, pbAlert)
				continue
			}
			c.dispatchAlert(pbAlert)
		case ready := <-c.isConnected:
			connected = ready
			if ready {
				log.Important("UI connected, dispathing queued alerts: %d", len(c.alertsChan))
				for {
					if isQueueEmpty(queuedAlerts) {
						// no more queued alerts, exit
						break
					}
					c.dispatchAlert(<-queuedAlerts)
				}
			}
		}
	}
}

func (c *Client) dispatchAlert(pbAlert protocol.Alert) {
	c.RLock()
	isDisconnected := c.client == nil
	c.RUnlock()
	if isDisconnected {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	c.client.PostAlert(ctx, &pbAlert, grpc.UseCompressor(gzip.Name))
	cancel()
}
