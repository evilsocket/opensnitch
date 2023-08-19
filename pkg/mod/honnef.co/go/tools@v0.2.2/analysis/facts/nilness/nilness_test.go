package nilness

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestNilness(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), Analysis, "Nilness")
}
