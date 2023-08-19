package netlink

import (
	"testing"
	"time"
)

func TestSetGetSocketTimeout(t *testing.T) {
	timeout := 10 * time.Second
	if err := SetSocketTimeout(10 * time.Second); err != nil {
		t.Fatalf("Set socket timeout for default handle failed: %v", err)
	}

	if val := GetSocketTimeout(); val != timeout {
		t.Fatalf("Unexpcted socket timeout value: got=%v, expected=%v", val, timeout)
	}
}
