// Package nftest contains utility functions for nftables testing.
package nftest

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

// Recorder provides an nftables connection that does not send to the Linux
// kernel but instead records netlink messages into the recorder. The recorded
// requests can later be obtained using Requests and compared using Diff.
type Recorder struct {
	requests []netlink.Message
}

// Conn opens an nftables connection that records netlink messages into the
// Recorder.
func (r *Recorder) Conn() (*nftables.Conn, error) {
	return nftables.New(nftables.WithTestDial(
		func(req []netlink.Message) ([]netlink.Message, error) {
			r.requests = append(r.requests, req...)

			acks := make([]netlink.Message, 0, len(req))
			for _, msg := range req {
				if msg.Header.Flags&netlink.Acknowledge != 0 {
					acks = append(acks, netlink.Message{
						Header: netlink.Header{
							Length:   4,
							Type:     netlink.Error,
							Sequence: msg.Header.Sequence,
							PID:      msg.Header.PID,
						},
						Data: []byte{0, 0, 0, 0},
					})
				}
			}
			return acks, nil
		}))
}

// Requests returns the recorded netlink messages (typically nftables requests).
func (r *Recorder) Requests() []netlink.Message {
	return r.requests
}

// NewRecorder returns a ready-to-use Recorder.
func NewRecorder() *Recorder {
	return &Recorder{}
}

// Diff returns the first difference between the specified netlink messages and
// the expected netlink message payloads.
func Diff(got []netlink.Message, want [][]byte) string {
	for idx, msg := range got {
		b, err := msg.MarshalBinary()
		if err != nil {
			return fmt.Sprintf("msg.MarshalBinary: %v", err)
		}
		if len(b) < 16 {
			continue
		}
		b = b[16:]
		if len(want) == 0 {
			return fmt.Sprintf("no want entry for message %d: %x", idx, b)
		}
		if got, want := b, want[0]; !bytes.Equal(got, want) {
			return fmt.Sprintf("message %d: %s", idx, linediff(nfdump(got), nfdump(want)))
		}
		want = want[1:]
	}
	return ""
}

// MatchRulesetBytes is a test helper that ensures the fillRuleset modifications
// correspond to the provided want netlink message payloads
func MatchRulesetBytes(t *testing.T, fillRuleset func(c *nftables.Conn), want [][]byte) {
	t.Helper()

	rec := NewRecorder()

	c, err := rec.Conn()
	if err != nil {
		t.Fatal(err)
	}

	c.FlushRuleset()

	fillRuleset(c)

	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}

	if diff := Diff(rec.Requests(), want); diff != "" {
		t.Errorf("unexpected netlink messages: diff: %s", diff)
	}
}

// nfdump returns a hexdump of 4 bytes per line (like nft --debug=all), allowing
// users to make sense of large byte literals more easily.
func nfdump(b []byte) string {
	var buf bytes.Buffer
	i := 0
	for ; i < len(b); i += 4 {
		// TODO: show printable characters as ASCII
		fmt.Fprintf(&buf, "%02x %02x %02x %02x\n",
			b[i],
			b[i+1],
			b[i+2],
			b[i+3])
	}
	for ; i < len(b); i++ {
		fmt.Fprintf(&buf, "%02x ", b[i])
	}
	return buf.String()
}

// linediff returns a side-by-side diff of two nfdump() return values, flagging
// lines which are not equal with an exclamation point prefix.
func linediff(a, b string) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "got -- want\n")
	linesA := strings.Split(a, "\n")
	linesB := strings.Split(b, "\n")
	for idx, lineA := range linesA {
		if idx >= len(linesB) {
			break
		}
		lineB := linesB[idx]
		prefix := "! "
		if lineA == lineB {
			prefix = "  "
		}
		fmt.Fprintf(&buf, "%s%s -- %s\n", prefix, lineA, lineB)
	}
	return buf.String()
}
