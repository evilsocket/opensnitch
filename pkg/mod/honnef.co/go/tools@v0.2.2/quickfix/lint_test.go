package quickfix

import (
	"testing"

	"honnef.co/go/tools/lint/testutil"
)

func TestAll(t *testing.T) {
	checks := map[string][]testutil.Test{
		"QF1000": {{Dir: "CheckStringsIndexByte"}},
		"QF1001": {{Dir: "CheckDeMorgan"}},
		"QF1002": {{Dir: "CheckTaglessSwitch"}},
		"QF1003": {{Dir: "CheckIfElseToSwitch"}},
		"QF1004": {{Dir: "CheckStringsReplaceAll"}},
		"QF1005": {{Dir: "CheckMathPow"}},
		"QF1006": {{Dir: "CheckForLoopIfBreak"}},
		"QF1007": {{Dir: "CheckConditionalAssignment"}},
		"QF1008": {{Dir: "CheckExplicitEmbeddedSelector"}},
		"QF1009": {{Dir: "CheckTimeEquality"}},
		"QF1010": {{Dir: "CheckByteSlicePrinting"}},
		"QF1011": {{Dir: "CheckRedundantTypeInDeclaration"}},
	}

	testutil.Run(t, Analyzers, checks)
}
