package tracepipe

import (
	"testing"
)

func TestParseTraceLine(t *testing.T) {
	testEvents := []struct {
		input    string
		expected TraceEvent
	}{
		{
			"        chromium-15581 [000] d... 92783.722567: : Hello, World!",
			TraceEvent{
				Task:     "chromium",
				Function: "",
				Message:  "Hello, World!",
			},
		},
		{
			"            curl-18597 [000] dN..   463.471554: : kretprobe__tcp_v4_connect - pid_tgid 79873506822309\n",
			TraceEvent{
				Task:     "curl",
				Function: "",
				Message:  "kretprobe__tcp_v4_connect - pid_tgid 79873506822309",
			},
		},
		{
			"      trace_pipe-23553 [000] .... 205825.968557: sys_enter: NR 0 (3, c420098000, 1000, 0, 0, 0)\n",
			TraceEvent{
				Task:     "trace_pipe",
				Function: "sys_enter",
				Message:  "NR 0 (3, c420098000, 1000, 0, 0, 0)",
			},
		},
		{
			"      trace_pipe-23553 [000] .... 205825.968557: sys_enter: hello: world\n",
			TraceEvent{
				Task:     "trace_pipe",
				Function: "sys_enter",
				Message:  "hello: world",
			},
		},
	}
	for _, testEvent := range testEvents {
		result, err := parseTraceLine(testEvent.input)
		if err != nil {
			t.Errorf("%q could not be parsed", testEvent.input)
		}
		if testEvent.expected.Task != result.Task {
			t.Errorf("result task %q doesn't match expected %q", result.Task, testEvent.expected.Task)
		}
		if testEvent.expected.Function != result.Function {
			t.Errorf("result function %q doesn't match expected %q", result.Function, testEvent.expected.Function)
		}
		if testEvent.expected.Message != result.Message {
			t.Errorf("result message %q doesn't match expected %q", result.Message, testEvent.expected.Message)
		}
	}
}
