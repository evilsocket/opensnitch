package ctxio_test

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/varlink/go/varlink/internal/ctxio"
)

func TestConn(t *testing.T) {
	l, err := net.Listen("tcp", ":")
	if err != nil {
		t.Fatalf("Unexpected error creating a listener: %v", err)
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := l.Accept()
		if err != nil {
			return
		}

		rd := bufio.NewReader(c)
		req, err := rd.ReadBytes('\n')
		if err != nil {
			t.Errorf("Failed to execute readFunc: %v", err)
			return
		}

		_, err = c.Write(append([]byte("Request received: "), req...))
		if err != nil {
			t.Errorf("Failed to execute writeFunc: %v", err)
			return
		}
	}()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial server: %v", err)
	}

	ctxC := ctxio.NewConn(c)

	_, err = ctxC.Write(context.Background(), []byte("hello world\n"))
	if err != nil {
		t.Fatalf("Failed to write request: %v", err)
	}

	ret, err := ctxC.ReadBytes(context.Background(), '\n')
	if err != nil {
		t.Fatalf("Failed to read reply: %v", err)
	}

	want := []byte("Request received: hello world\n")
	if !bytes.Equal(ret, want) {
		t.Fatalf("Unexpected response: wanted %q, got %q", string(want), string(ret))
	}

	err = ctxC.Close()
	if err != nil {
		t.Fatalf("Failed to close ctx connection: %v", err)
	}

	err = l.Close()
	if err != nil {
		t.Fatalf("Failed to close listener: %v", err)
	}

	wg.Wait()
}

func TestBlockingWrite(t *testing.T) {
	cl, _ := net.Pipe()

	ctxC := ctxio.NewConn(cl)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(time.Millisecond)
		cancel()
	}()
	_, err := ctxC.Write(ctx, []byte("hello world\n"))
	if err == nil {
		t.Fatal("Unexpectedly did not error")
	}
	if err != context.Canceled {
		t.Fatalf("Got unexpected error: %T, %s", err, err)
	}
}

func TestBlockingRead(t *testing.T) {
	cl, _ := net.Pipe()

	ctxC := ctxio.NewConn(cl)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(time.Millisecond)
		cancel()
	}()
	_, err := ctxC.ReadBytes(ctx, '\n')
	if err == nil {
		t.Fatal("Unexpectedly did not error")
	}
	if err != context.Canceled {
		t.Fatalf("Got unexpected error: %T, %s", err, err)
	}
}
