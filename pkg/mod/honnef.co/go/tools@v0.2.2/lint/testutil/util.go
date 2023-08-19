package testutil

import (
	"testing"

	"honnef.co/go/tools/analysis/lint"

	"golang.org/x/tools/go/analysis/analysistest"
)

type Test struct {
	Dir     string
	Version string
}

func Run(t *testing.T, analyzers []*lint.Analyzer, tests map[string][]Test) {
	for _, a := range analyzers {
		a := a
		t.Run(a.Analyzer.Name, func(t *testing.T) {
			t.Parallel()
			tt, ok := tests[a.Analyzer.Name]
			if !ok {
				t.Fatalf("no tests for analyzer %s", a.Analyzer.Name)
			}
			for _, test := range tt {
				if test.Version != "" {
					if err := a.Analyzer.Flags.Lookup("go").Value.Set(test.Version); err != nil {
						t.Fatal(err)
					}
				}
				analysistest.RunWithSuggestedFixes(t, analysistest.TestData(), a.Analyzer, test.Dir)
			}
		})
	}
}
