package typedness

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestTypedness(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), Analysis, "Typedness")
}
