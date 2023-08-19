//go:build go1.12 && linux
// +build go1.12,linux

package netlink

// This file exports certain identifiers for use in tests.

// A NetNS wraps an internal netNS.
type NetNS struct {
	*netNS
}

// ThreadNetNS wraps the internal threadNetNS.
func ThreadNetNS() (*NetNS, error) {
	ns, err := threadNetNS()
	if err != nil {
		return nil, err
	}

	return &NetNS{netNS: ns}, nil
}
