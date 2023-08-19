package native_test

import (
	"testing"

	"github.com/josharian/native"
)

func TestPrintEndianness(t *testing.T) {
	t.Logf("native endianness is %v", native.Endian)
}
