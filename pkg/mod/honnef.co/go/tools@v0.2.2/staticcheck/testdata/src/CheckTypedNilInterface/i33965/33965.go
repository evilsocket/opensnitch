package pkg

import (
	"fmt"
	"testing"
)

type customError struct {
}

func (p *customError) Error() string {
	return "custom error"
}

func getNilCustomError() *customError {
	return nil
}

func TestWebSocketClient_basic(t *testing.T) {
	err1 := getNilCustomError()
	fmt.Println(err1 == nil) // ok is true

	err2 := error(nil)
	err2 = getNilCustomError()
	fmt.Println(err2 == nil) // want `this comparison is never true`
}
