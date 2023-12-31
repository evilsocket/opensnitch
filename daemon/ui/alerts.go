package ui

import (
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
	}

	return a
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
