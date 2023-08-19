package stylecheck

import (
	"testing"

	"honnef.co/go/tools/lint/testutil"
)

func TestAll(t *testing.T) {
	checks := map[string][]testutil.Test{
		"ST1000": {{Dir: "CheckPackageComment-1"}, {Dir: "CheckPackageComment-2"}, {Dir: "CheckPackageComment-3"}},
		"ST1001": {{Dir: "CheckDotImports"}},
		"ST1003": {{Dir: "CheckNames"}, {Dir: "CheckNames_generated"}},
		"ST1005": {{Dir: "CheckErrorStrings"}},
		"ST1006": {{Dir: "CheckReceiverNames"}},
		"ST1008": {{Dir: "CheckErrorReturn"}},
		"ST1011": {{Dir: "CheckTimeNames"}},
		"ST1012": {{Dir: "CheckErrorVarNames"}},
		"ST1013": {{Dir: "CheckHTTPStatusCodes"}},
		"ST1015": {{Dir: "CheckDefaultCaseOrder"}},
		"ST1016": {{Dir: "CheckReceiverNamesIdentical"}},
		"ST1017": {{Dir: "CheckYodaConditions"}},
		"ST1018": {{Dir: "CheckInvisibleCharacters"}},
		"ST1019": {{Dir: "CheckDuplicatedImports"}},
		"ST1020": {{Dir: "CheckExportedFunctionDocs"}},
		"ST1021": {{Dir: "CheckExportedTypeDocs"}},
		"ST1022": {{Dir: "CheckExportedVarDocs"}},
		"ST1023": {{Dir: "CheckRedundantTypeInDeclaration"}, {Dir: "CheckRedundantTypeInDeclaration_syscall"}},
	}

	testutil.Run(t, Analyzers, checks)
}
