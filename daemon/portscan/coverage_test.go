package portscan

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryTechniqueHasAReason: a detectability status with no reason is an
// opinion. The point of the taxonomy is that "this cannot be detected" is a
// claim someone can check, not a to-do item in disguise.
func TestEveryTechniqueHasAReason(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range Techniques {
		if tc.Name == "" {
			t.Fatalf("a technique has no name")
		}
		if seen[tc.Name] {
			t.Errorf("%q appears twice in the taxonomy", tc.Name)
		}
		seen[tc.Name] = true

		if strings.TrimSpace(tc.Why) == "" {
			t.Errorf("%q has no reason recorded", tc.Name)
		}
		if len(tc.Why) < 40 {
			t.Errorf("%q: the reason %q is too short to be one", tc.Name, tc.Why)
		}
		switch tc.Scan {
		case DetectFull, DetectPartial, DetectIndirect, Unreachable, OutOfScope:
		default:
			t.Errorf("%q has an unknown scan status %q", tc.Name, tc.Scan)
		}
		switch tc.Attribution {
		case DetectFull, DetectPartial, DetectIndirect, Unreachable, OutOfScope:
		default:
			t.Errorf("%q has an unknown attribution status %q", tc.Name, tc.Attribution)
		}
	}
}

// TestEveryCaptureBelongsToATechnique closes the taxonomy against the corpus in
// both directions: a capture nobody claims would be an untracked expectation,
// and a claimed capture that does not exist would be a coverage report citing
// evidence that was never produced.
func TestEveryCaptureBelongsToATechnique(t *testing.T) {
	requireCorpus(t)

	entries, err := os.ReadDir(corpusDir())
	if err != nil {
		t.Fatalf("reading the corpus: %v", err)
	}
	onDisk := map[string]bool{}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".pcap" {
			onDisk[strings.TrimSuffix(e.Name(), ".pcap")] = true
		}
	}

	claimed := map[string]string{}
	for _, tc := range Techniques {
		if tc.Corpus == "" {
			continue
		}
		if other, dup := claimed[tc.Corpus]; dup {
			t.Errorf("%s.pcap is claimed by both %q and %q", tc.Corpus, other, tc.Name)
		}
		claimed[tc.Corpus] = tc.Name
		if !onDisk[tc.Corpus] {
			t.Errorf("%q cites %s.pcap, which is not in the corpus", tc.Name, tc.Corpus)
		}
	}
	for name := range onDisk {
		if _, ok := claimed[name]; !ok {
			t.Errorf("%s.pcap is in the corpus but no technique claims it", name)
		}
	}
}

// TestTaxonomyAgreesWithTheDifferentialOracle: the corpus expectations and the
// published taxonomy are two statements about the same captures. They are kept
// separate on purpose -- one drives the tests, the other the documentation --
// so they are checked against each other rather than trusted to stay in step.
func TestTaxonomyAgreesWithTheDifferentialOracle(t *testing.T) {
	byCorpus := map[string]Technique{}
	for _, tc := range Techniques {
		if tc.Corpus != "" {
			byCorpus[tc.Corpus] = tc
		}
	}

	for _, c := range corpusCases {
		tc, ok := byCorpus[c.file]
		if !ok {
			t.Errorf("the differential corpus uses %s.pcap, which the taxonomy does not list", c.file)
			continue
		}
		if c.wantMethod != MethodUnknown && tc.Expect != MethodUnknown && c.wantMethod != tc.Expect {
			t.Errorf("%s: the oracle expects %v, the taxonomy says %v", c.file, c.wantMethod, tc.Expect)
		}
		// A capture the oracle says must NOT be reported cannot be described as
		// fully detectable.
		if !c.wantDetected && tc.Scan == DetectFull {
			t.Errorf("%s: the oracle requires no detection, but the taxonomy claims %s",
				c.file, DetectFull)
		}
	}
}

// TestRenderCoverageIsHonestAboutWhatItDidNotRun: a report that quietly omits
// the techniques it could not exercise is the kind of coverage claim this
// project exists not to make.
func TestRenderCoverageIsHonestAboutWhatItDidNotRun(t *testing.T) {
	var buf bytes.Buffer
	// Deliberately empty: nothing was replayed.
	if err := RenderCoverage(&buf, DefaultConfig(), nil); err != nil {
		t.Fatalf("RenderCoverage: %v", err)
	}
	out := buf.String()

	for _, tc := range Techniques {
		if !strings.Contains(out, escapePipes(tc.Name)) {
			t.Errorf("the report omits %q", tc.Name)
		}
	}
	if !strings.Contains(out, "not exercised here") {
		t.Errorf("the report does not say which techniques were not exercised")
	}
	for _, code := range []Detectability{DetectFull, DetectPartial, Unreachable, OutOfScope} {
		if !strings.Contains(out, string(code)) {
			t.Errorf("the report never mentions %s", code)
		}
	}
	if strings.Contains(out, "100%") {
		t.Errorf("the report claims a percentage; coverage here is a status per technique, not a score")
	}
}

// TestRenderCoverageDerivesTheTimingLimits: the slowest detectable scan is a
// consequence of the configuration, so the report must compute it rather than
// restate a number someone typed once.
func TestRenderCoverageDerivesTheTimingLimits(t *testing.T) {
	cfg := DefaultConfig()
	var slow bytes.Buffer
	if err := RenderCoverage(&slow, cfg, nil); err != nil {
		t.Fatalf("RenderCoverage: %v", err)
	}

	cfg.DecayInterval = cfg.DecayInterval / 10
	var fast bytes.Buffer
	if err := RenderCoverage(&fast, cfg, nil); err != nil {
		t.Fatalf("RenderCoverage: %v", err)
	}

	if slow.String() == fast.String() {
		t.Fatalf("changing the decay interval did not change the reported limits: they are not derived")
	}
}

// TestRenderCoverageEscapesTableCells guards the one technique whose name
// contains the Markdown table separator.
func TestRenderCoverageEscapesTableCells(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderCoverage(&buf, DefaultConfig(), nil); err != nil {
		t.Fatalf("RenderCoverage: %v", err)
	}
	// Every row of a table must have as many unescaped separators as the header
	// that opened it. A name containing a bare "|" would add one and silently
	// shift every cell after it.
	unescaped := func(line string) int {
		n := 0
		for i := 0; i < len(line); i++ {
			if line[i] == '|' && (i == 0 || line[i-1] != '\\') {
				n++
			}
		}
		return n
	}

	want := 0
	for i, line := range strings.Split(buf.String(), "\n") {
		isRow := strings.HasPrefix(line, "|") && strings.HasSuffix(line, "|")
		if !isRow {
			want = 0 // the table ended
			continue
		}
		if want == 0 {
			want = unescaped(line) // this is the header
			continue
		}
		if got := unescaped(line); got != want {
			t.Errorf("line %d has %d separators, the table header has %d; the row will not render:\n%s",
				i+1, got, want, line)
		}
	}
	if want == 0 && !strings.Contains(buf.String(), "|") {
		t.Fatalf("the report contains no table at all")
	}
}

// TestCorpusNamesIsSorted keeps the generated report deterministic: the same
// corpus must produce byte-identical output on every run, or the -check mode
// would fail at random.
func TestCorpusNamesIsSorted(t *testing.T) {
	names := CorpusNames()
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("CorpusNames is not sorted: %q before %q", names[i-1], names[i])
		}
	}
	if len(names) == 0 {
		t.Fatalf("no technique cites a capture")
	}
}
