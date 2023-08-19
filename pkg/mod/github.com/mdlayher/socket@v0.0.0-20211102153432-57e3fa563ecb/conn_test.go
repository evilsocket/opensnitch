package socket_test

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mdlayher/socket"
	"golang.org/x/net/nettest"
	"golang.org/x/sys/unix"
)

func TestConn(t *testing.T) {
	// Use our TCP net.Listener and net.Conn implementations backed by *socket.Conn
	// and run compliance tests with nettest.TestConn.
	//
	// This nettest.MakePipe function is adapted from nettest's own tests:
	// https://github.com/golang/net/blob/master/nettest/conntest_test.go
	//
	// Copyright 2016 The Go Authors. All rights reserved. Use of this source
	// code is governed by a BSD-style license that can be found in the LICENSE
	// file.
	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
		ln, err := listen()
		if err != nil {
			return nil, nil, nil, err
		}

		// Start a connection between two endpoints.
		var err1, err2 error
		done := make(chan bool)
		go func() {
			c2, err2 = ln.Accept()
			close(done)
		}()
		c1, err1 = dial(ln.Addr().(*net.TCPAddr))
		<-done

		stop = func() {
			if err1 == nil {
				c1.Close()
			}
			if err2 == nil {
				c2.Close()
			}
			ln.Close()
		}

		switch {
		case err1 != nil:
			stop()
			return nil, nil, nil, err1
		case err2 != nil:
			stop()
			return nil, nil, nil, err2
		default:
			return c1, c2, stop, nil
		}
	})
}

type tcpListener struct {
	addr *net.TCPAddr
	c    *socket.Conn
}

func listen() (net.Listener, error) {
	c, err := socket.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0, "tcpv6-server")
	if err != nil {
		return nil, fmt.Errorf("failed to open socket: %v", err)
	}

	if err := c.Bind(&unix.SockaddrInet6{}); err != nil {
		return nil, fmt.Errorf("failed to bind: %v", err)
	}

	if err := c.Listen(unix.SOMAXCONN); err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}

	sa, err := c.Getsockname()
	if err != nil {
		return nil, fmt.Errorf("failed to getsockname: %v", err)
	}

	return &tcpListener{
		addr: newTCPAddr(sa),
		c:    c,
	}, nil
}

func (l *tcpListener) Addr() net.Addr { return l.addr }
func (l *tcpListener) Close() error   { return l.c.Close() }

func (l *tcpListener) Accept() (net.Conn, error) {
	// SOCK_CLOEXEC and SOCK_NONBLOCK set automatically by Accept when possible.
	c, rsa, err := l.c.Accept(0)
	if err != nil {
		return nil, err
	}

	lsa, err := c.Getsockname()
	if err != nil {
		return nil, err
	}

	return &tcpConn{
		local:  newTCPAddr(lsa),
		remote: newTCPAddr(rsa),
		c:      c,
	}, nil
}

type tcpConn struct {
	local, remote *net.TCPAddr
	c             *socket.Conn
}

func dial(addr *net.TCPAddr) (net.Conn, error) {
	c, err := socket.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0, "tcpv6-client")
	if err != nil {
		return nil, fmt.Errorf("failed to open socket: %v", err)
	}

	var sa unix.SockaddrInet6
	copy(sa.Addr[:], addr.IP)
	sa.Port = addr.Port

	if err := c.Connect(&sa); err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}

	lsa, err := c.Getsockname()
	if err != nil {
		return nil, err
	}

	return &tcpConn{
		local:  newTCPAddr(lsa),
		remote: addr,
		c:      c,
	}, nil
}

func (c *tcpConn) Close() error                       { return c.c.Close() }
func (c *tcpConn) LocalAddr() net.Addr                { return c.local }
func (c *tcpConn) RemoteAddr() net.Addr               { return c.remote }
func (c *tcpConn) SetDeadline(t time.Time) error      { return c.c.SetDeadline(t) }
func (c *tcpConn) SetReadDeadline(t time.Time) error  { return c.c.SetReadDeadline(t) }
func (c *tcpConn) SetWriteDeadline(t time.Time) error { return c.c.SetWriteDeadline(t) }

func (c *tcpConn) Read(b []byte) (int, error) {
	n, err := c.c.Read(b)
	return n, opError("read", err)
}

func (c *tcpConn) Write(b []byte) (int, error) {
	n, err := c.c.Write(b)
	return n, opError("write", err)
}

func opError(op string, err error) error {
	// This is still a bit simplistic but sufficient for nettest.TestConn.
	switch err {
	case nil:
		return nil
	case io.EOF:
		return io.EOF
	default:
		return &net.OpError{Op: op, Err: err}
	}
}

func newTCPAddr(sa unix.Sockaddr) *net.TCPAddr {
	sa6 := sa.(*unix.SockaddrInet6)
	return &net.TCPAddr{
		IP:   sa6.Addr[:],
		Port: sa6.Port,
	}
}
