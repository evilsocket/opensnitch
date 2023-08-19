//go:build !linux
// +build !linux

package netlink

import "testing"

func TestOthersConnUnimplemented(t *testing.T) {
	c := &conn{}
	want := errUnimplemented

	if got := newError(0); want != got {
		t.Fatalf("unexpected error during newError:\n- want: %v\n-  got: %v",
			want, got)
	}

	if _, _, got := dial(0, nil); want != got {
		t.Fatalf("unexpected error during dial:\n- want: %v\n-  got: %v",
			want, got)
	}

	if got := c.Send(Message{}); want != got {
		t.Fatalf("unexpected error during c.Send:\n- want: %v\n-  got: %v",
			want, got)
	}

	if got := c.SendMessages(nil); want != got {
		t.Fatalf("unexpected error during c.SendMessages:\n- want: %v\n-  got: %v",
			want, got)
	}

	if _, got := c.Receive(); want != got {
		t.Fatalf("unexpected error during c.Receive:\n- want: %v\n-  got: %v",
			want, got)
	}

	if got := c.Close(); want != got {
		t.Fatalf("unexpected error during c.Close:\n- want: %v\n-  got: %v",
			want, got)
	}
}
