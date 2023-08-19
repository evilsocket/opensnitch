package varlink

// tests with access to internals

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func expect(t *testing.T, expected string, returned string) {
	if strings.Compare(returned, expected) != 0 {
		t.Fatalf("Expected(%d): `%s`\nGot(%d): `%s`\n",
			len(expected), expected,
			len(returned), strings.Replace(returned, "\000", "`+\"\\000\"+`", -1))
	}
}

type readWriterContextFunc func(context.Context, []byte) (int, error)

func (wcf readWriterContextFunc) Write(ctx context.Context, in []byte) (int, error) {
	return wcf(ctx, in)
}

func (wcf readWriterContextFunc) Read(context.Context, []byte) (int, error) {
	return 0, nil
}

func (wcf readWriterContextFunc) ReadBytes(context.Context, byte) ([]byte, error) {
	return nil, nil
}

func TestService(t *testing.T) {
	service, _ := NewService(
		"Varlink",
		"Varlink Test",
		"1",
		"https://github.com/varlink/go/varlink",
	)

	t.Run("ZeroMessage", func(t *testing.T) {
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			return 0, nil
		})
		if err := service.HandleMessage(context.Background(), wf, []byte{0}); err == nil {
			t.Fatal("HandleMessage returned non-error")
		}
	})

	t.Run("InvalidJson", func(t *testing.T) {
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			return 0, nil
		})
		msg := []byte(`{"method":"foo.GetInterfaceDescription" fdgdfg}`)
		if err := service.HandleMessage(context.Background(), wf, msg); err == nil {
			t.Fatal("HandleMessage returned no error on invalid json")
		}
	})

	t.Run("WrongInterface", func(t *testing.T) {
		var written []byte
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			written = append(written, in...)
			return len(in), nil
		})
		msg := []byte(`{"method":"foo.GetInterfaceDescription"}`)
		if err := service.HandleMessage(context.Background(), wf, msg); err != nil {
			t.Fatal("HandleMessage returned error on wrong interface")
		}
		expect(t, `{"parameters":{"interface":"foo"},"error":"org.varlink.service.InterfaceNotFound"}`+"\000",
			string(written))
	})
	t.Run("InvalidMethod", func(t *testing.T) {
		var written []byte
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			written = append(written, in...)
			return len(in), nil
		})
		msg := []byte(`{"method":"InvalidMethod"}`)
		if err := service.HandleMessage(context.Background(), wf, msg); err != nil {
			t.Fatal("HandleMessage returned error on invalid method")
		}
		expect(t, `{"parameters":{"parameter":"method"},"error":"org.varlink.service.InvalidParameter"}`+"\000",
			string(written))
	})

	t.Run("WrongMethod", func(t *testing.T) {
		var written []byte
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			written = append(written, in...)
			return len(in), nil
		})
		msg := []byte(`{"method":"org.varlink.service.WrongMethod"}`)
		if err := service.HandleMessage(context.Background(), wf, msg); err != nil {
			t.Fatal("HandleMessage returned error on wrong method")
		}
		expect(t, `{"parameters":{"method":"WrongMethod"},"error":"org.varlink.service.MethodNotFound"}`+"\000",
			string(written))
	})

	t.Run("GetInterfaceDescriptionNullParameters", func(t *testing.T) {
		var written []byte
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			written = append(written, in...)
			return len(in), nil
		})
		msg := []byte(`{"method":"org.varlink.service.GetInterfaceDescription","parameters": null}`)
		if err := service.HandleMessage(context.Background(), wf, msg); err != nil {
			t.Fatalf("HandleMessage returned error: %v", err)
		}
		expect(t, `{"parameters":{"parameter":"parameters"},"error":"org.varlink.service.InvalidParameter"}`+"\000",
			string(written))
	})

	t.Run("GetInterfaceDescriptionNoInterface", func(t *testing.T) {
		var written []byte
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			written = append(written, in...)
			return len(in), nil
		})
		msg := []byte(`{"method":"org.varlink.service.GetInterfaceDescription","parameters":{}}`)
		if err := service.HandleMessage(context.Background(), wf, msg); err != nil {
			t.Fatalf("HandleMessage returned error: %v", err)
		}
		expect(t, `{"parameters":{"parameter":"interface"},"error":"org.varlink.service.InvalidParameter"}`+"\000",
			string(written))
	})

	t.Run("GetInterfaceDescriptionWrongInterface", func(t *testing.T) {
		var written []byte
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			written = append(written, in...)
			return len(in), nil
		})
		msg := []byte(`{"method":"org.varlink.service.GetInterfaceDescription","parameters":{"interface":"foo"}}`)
		if err := service.HandleMessage(context.Background(), wf, msg); err != nil {
			t.Fatalf("HandleMessage returned error: %v", err)
		}
		expect(t, `{"parameters":{"parameter":"interface"},"error":"org.varlink.service.InvalidParameter"}`+"\000",
			string(written))
	})

	t.Run("GetInterfaceDescription", func(t *testing.T) {
		var written []byte
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			written = append(written, in...)
			return len(in), nil
		})
		msg := []byte(`{"method":"org.varlink.service.GetInterfaceDescription","parameters":{"interface":"org.varlink.service"}}`)
		if err := service.HandleMessage(context.Background(), wf, msg); err != nil {
			t.Fatalf("HandleMessage returned error: %v", err)
		}
		expect(t, `{"parameters":{"description":"# The Varlink Service Interface is provided by every varlink service. It\n# describes the service and the interfaces it implements.\ninterface org.varlink.service\n\n# Get a list of all the interfaces a service provides and information\n# about the implementation.\nmethod GetInfo() -\u003e (\n  vendor: string,\n  product: string,\n  version: string,\n  url: string,\n  interfaces: []string\n)\n\n# Get the description of an interface that is implemented by this service.\nmethod GetInterfaceDescription(interface: string) -\u003e (description: string)\n\n# The requested interface was not found.\nerror InterfaceNotFound (interface: string)\n\n# The requested method was not found\nerror MethodNotFound (method: string)\n\n# The interface defines the requested method, but the service does not\n# implement it.\nerror MethodNotImplemented (method: string)\n\n# One of the passed parameters is invalid.\nerror InvalidParameter (parameter: string)"}}`+"\000",
			string(written))
	})

	t.Run("GetInfo", func(t *testing.T) {
		var written []byte
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			written = append(written, in...)
			return len(in), nil
		})
		msg := []byte(`{"method":"org.varlink.service.GetInfo"}`)
		if err := service.HandleMessage(context.Background(), wf, msg); err != nil {
			t.Fatalf("HandleMessage returned error: %v", err)
		}
		expect(t, `{"parameters":{"vendor":"Varlink","product":"Varlink Test","version":"1","url":"https://github.com/varlink/go/varlink","interfaces":["org.varlink.service"]}}`+"\000",
			string(written))
	})
}

type VarlinkInterface struct{}

func (s *VarlinkInterface) VarlinkDispatch(ctx context.Context, call Call, methodname string) error {
	switch methodname {
	case "Ping":
		if !call.WantsMore() {
			return fmt.Errorf("More flag not passed")
		}
		if call.IsOneway() {
			return fmt.Errorf("OneShot flag set")
		}
		call.Continues = true
		if err := call.Reply(ctx, nil); err != nil {
			return err
		}
		if err := call.Reply(ctx, nil); err != nil {
			return err
		}
		call.Continues = false
		if err := call.Reply(ctx, nil); err != nil {
			return err
		}
		return nil

	case "PingError":
		return call.ReplyError(ctx, "org.example.test.PingError", nil)
	}

	call.Continues = true
	if err := call.Reply(ctx, nil); err == nil {
		return fmt.Errorf("call.Reply did not fail for Continues/More mismatch")
	}
	call.Continues = false

	if err := call.ReplyError(ctx, "WrongName", nil); err == nil {
		return fmt.Errorf("call.ReplyError accepted invalid error name")
	}

	if err := call.ReplyError(ctx, "org.varlink.service.MethodNotImplemented", nil); err == nil {
		return fmt.Errorf("call.ReplyError accepted org.varlink.service error")
	}

	return call.ReplyMethodNotImplemented(ctx, methodname)
}

func (s *VarlinkInterface) VarlinkGetName() string {
	return `org.example.test`
}

func (s *VarlinkInterface) VarlinkGetDescription() string {
	return "#"
}

func TestMoreService(t *testing.T) {
	newTestInterface := new(VarlinkInterface)

	service, _ := NewService(
		"Varlink",
		"Varlink Test",
		"1",
		"https://github.com/varlink/go/varlink",
	)

	if err := service.RegisterInterface(newTestInterface); err != nil {
		t.Fatalf("Couldn't register service: %v", err)
	}

	t.Run("MethodNotImplemented", func(t *testing.T) {
		var written []byte
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			written = append(written, in...)
			return len(in), nil
		})
		msg := []byte(`{"method":"org.example.test.Pingf"}`)
		if err := service.HandleMessage(context.Background(), wf, msg); err != nil {
			t.Fatalf("HandleMessage returned error: %v", err)
		}
		expect(t, `{"parameters":{"method":"Pingf"},"error":"org.varlink.service.MethodNotImplemented"}`+"\000",
			string(written))
	})

	t.Run("PingError", func(t *testing.T) {
		var written []byte
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			written = append(written, in...)
			return len(in), nil
		})
		msg := []byte(`{"method":"org.example.test.PingError", "more" : true}`)
		if err := service.HandleMessage(context.Background(), wf, msg); err != nil {
			t.Fatalf("HandleMessage returned error: %v", err)
		}
		expect(t, `{"error":"org.example.test.PingError"}`+"\000",
			string(written))
	})
	t.Run("MoreTest", func(t *testing.T) {
		var written []byte
		wf := readWriterContextFunc(func(ctx context.Context, in []byte) (int, error) {
			written = append(written, in...)
			return len(in), nil
		})
		msg := []byte(`{"method":"org.example.test.Ping", "more" : true}`)
		if err := service.HandleMessage(context.Background(), wf, msg); err != nil {
			t.Fatalf("HandleMessage returned error: %v", err)
		}
		expect(t, `{"continues":true}`+"\000"+`{"continues":true}`+"\000"+`{}`+"\000",
			string(written))
	})
}
