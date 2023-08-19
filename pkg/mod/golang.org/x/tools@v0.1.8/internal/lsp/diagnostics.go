// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lsp

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/tools/internal/event"
	"golang.org/x/tools/internal/lsp/debug/log"
	"golang.org/x/tools/internal/lsp/debug/tag"
	"golang.org/x/tools/internal/lsp/mod"
	"golang.org/x/tools/internal/lsp/protocol"
	"golang.org/x/tools/internal/lsp/source"
	"golang.org/x/tools/internal/lsp/template"
	"golang.org/x/tools/internal/span"
	"golang.org/x/tools/internal/xcontext"
	errors "golang.org/x/xerrors"
)

// diagnosticSource differentiates different sources of diagnostics.
type diagnosticSource int

const (
	modSource diagnosticSource = iota
	gcDetailsSource
	analysisSource
	typeCheckSource
	orphanedSource
)

// A diagnosticReport holds results for a single diagnostic source.
type diagnosticReport struct {
	snapshotID    uint64
	publishedHash string
	diags         map[string]*source.Diagnostic
}

// fileReports holds a collection of diagnostic reports for a single file, as
// well as the hash of the last published set of diagnostics.
type fileReports struct {
	snapshotID    uint64
	publishedHash string
	reports       map[diagnosticSource]diagnosticReport
}

func (d diagnosticSource) String() string {
	switch d {
	case modSource:
		return "FromSource"
	case gcDetailsSource:
		return "FromGCDetails"
	case analysisSource:
		return "FromAnalysis"
	case typeCheckSource:
		return "FromTypeChecking"
	case orphanedSource:
		return "FromOrphans"
	default:
		return fmt.Sprintf("From?%d?", d)
	}
}

// hashDiagnostics computes a hash to identify diags.
func hashDiagnostics(diags ...*source.Diagnostic) string {
	source.SortDiagnostics(diags)
	h := sha256.New()
	for _, d := range diags {
		for _, t := range d.Tags {
			fmt.Fprintf(h, "%s", t)
		}
		for _, r := range d.Related {
			fmt.Fprintf(h, "%s%s%s", r.URI, r.Message, r.Range)
		}
		fmt.Fprintf(h, "%s%s%s%s", d.Message, d.Range, d.Severity, d.Source)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (s *Server) diagnoseDetached(snapshot source.Snapshot) {
	ctx := snapshot.BackgroundContext()
	ctx = xcontext.Detach(ctx)
	s.diagnose(ctx, snapshot, false)
	s.publishDiagnostics(ctx, true, snapshot)
}

func (s *Server) diagnoseSnapshots(snapshots map[source.Snapshot][]span.URI, onDisk bool) {
	var diagnosticWG sync.WaitGroup
	for snapshot, uris := range snapshots {
		diagnosticWG.Add(1)
		go func(snapshot source.Snapshot, uris []span.URI) {
			defer diagnosticWG.Done()
			s.diagnoseSnapshot(snapshot, uris, onDisk)
		}(snapshot, uris)
	}
	diagnosticWG.Wait()
}

func (s *Server) diagnoseSnapshot(snapshot source.Snapshot, changedURIs []span.URI, onDisk bool) {
	ctx := snapshot.BackgroundContext()
	ctx, done := event.Start(ctx, "Server.diagnoseSnapshot", tag.Snapshot.Of(snapshot.ID()))
	defer done()

	delay := snapshot.View().Options().DiagnosticsDelay
	if delay > 0 {
		// 2-phase diagnostics.
		//
		// The first phase just parses and checks packages that have been
		// affected by file modifications (no analysis).
		//
		// The second phase does everything, and is debounced by the configured
		// delay.
		s.diagnoseChangedFiles(ctx, snapshot, changedURIs, onDisk)
		s.publishDiagnostics(ctx, false, snapshot)
		if ok := <-s.diagDebouncer.debounce(snapshot.View().Name(), snapshot.ID(), time.After(delay)); ok {
			s.diagnose(ctx, snapshot, false)
			s.publishDiagnostics(ctx, true, snapshot)
		}
		return
	}

	// Ignore possible workspace configuration warnings in the normal flow.
	s.diagnose(ctx, snapshot, false)
	s.publishDiagnostics(ctx, true, snapshot)
}

func (s *Server) diagnoseChangedFiles(ctx context.Context, snapshot source.Snapshot, uris []span.URI, onDisk bool) {
	ctx, done := event.Start(ctx, "Server.diagnoseChangedFiles", tag.Snapshot.Of(snapshot.ID()))
	defer done()

	packages := make(map[source.Package]struct{})
	for _, uri := range uris {
		// If the change is only on-disk and the file is not open, don't
		// directly request its package. It may not be a workspace package.
		if onDisk && !snapshot.IsOpen(uri) {
			continue
		}
		// If the file is not known to the snapshot (e.g., if it was deleted),
		// don't diagnose it.
		if snapshot.FindFile(uri) == nil {
			continue
		}
		// Don't call PackagesForFile for builtin.go, as it results in a
		// command-line-arguments load.
		if snapshot.IsBuiltin(ctx, uri) {
			continue
		}
		pkgs, err := snapshot.PackagesForFile(ctx, uri, source.TypecheckFull, false)
		if err != nil {
			// TODO (findleyr): we should probably do something with the error here,
			// but as of now this can fail repeatedly if load fails, so can be too
			// noisy to log (and we'll handle things later in the slow pass).
			continue
		}
		for _, pkg := range pkgs {
			packages[pkg] = struct{}{}
		}
	}
	var wg sync.WaitGroup
	for pkg := range packages {
		wg.Add(1)

		go func(pkg source.Package) {
			defer wg.Done()

			s.diagnosePkg(ctx, snapshot, pkg, false)
		}(pkg)
	}
	wg.Wait()
}

// diagnose is a helper function for running diagnostics with a given context.
// Do not call it directly. forceAnalysis is only true for testing purposes.
func (s *Server) diagnose(ctx context.Context, snapshot source.Snapshot, forceAnalysis bool) {
	ctx, done := event.Start(ctx, "Server.diagnose", tag.Snapshot.Of(snapshot.ID()))
	defer done()

	// Wait for a free diagnostics slot.
	select {
	case <-ctx.Done():
		return
	case s.diagnosticsSema <- struct{}{}:
	}
	defer func() {
		<-s.diagnosticsSema
	}()

	// First, diagnose the go.mod file.
	modReports, modErr := mod.Diagnostics(ctx, snapshot)
	if ctx.Err() != nil {
		log.Trace.Log(ctx, "diagnose cancelled")
		return
	}
	if modErr != nil {
		event.Error(ctx, "warning: diagnose go.mod", modErr, tag.Directory.Of(snapshot.View().Folder().Filename()), tag.Snapshot.Of(snapshot.ID()))
	}
	for id, diags := range modReports {
		if id.URI == "" {
			event.Error(ctx, "missing URI for module diagnostics", fmt.Errorf("empty URI"), tag.Directory.Of(snapshot.View().Folder().Filename()))
			continue
		}
		s.storeDiagnostics(snapshot, id.URI, modSource, diags)
	}

	// Diagnose all of the packages in the workspace.
	wsPkgs, err := snapshot.ActivePackages(ctx)
	if s.shouldIgnoreError(ctx, snapshot, err) {
		return
	}
	criticalErr := snapshot.GetCriticalError(ctx)

	// Show the error as a progress error report so that it appears in the
	// status bar. If a client doesn't support progress reports, the error
	// will still be shown as a ShowMessage. If there is no error, any running
	// error progress reports will be closed.
	s.showCriticalErrorStatus(ctx, snapshot, criticalErr)

	// There may be .tmpl files.
	for _, f := range snapshot.Templates() {
		diags := template.Diagnose(f)
		s.storeDiagnostics(snapshot, f.URI(), typeCheckSource, diags)
	}

	// If there are no workspace packages, there is nothing to diagnose and
	// there are no orphaned files.
	if len(wsPkgs) == 0 {
		return
	}

	var (
		wg   sync.WaitGroup
		seen = map[span.URI]struct{}{}
	)
	for _, pkg := range wsPkgs {
		wg.Add(1)

		for _, pgf := range pkg.CompiledGoFiles() {
			seen[pgf.URI] = struct{}{}
		}

		go func(pkg source.Package) {
			defer wg.Done()

			s.diagnosePkg(ctx, snapshot, pkg, forceAnalysis)
		}(pkg)
	}
	wg.Wait()

	// Confirm that every opened file belongs to a package (if any exist in
	// the workspace). Otherwise, add a diagnostic to the file.
	for _, o := range s.session.Overlays() {
		if _, ok := seen[o.URI()]; ok {
			continue
		}
		diagnostic := s.checkForOrphanedFile(ctx, snapshot, o)
		if diagnostic == nil {
			continue
		}
		s.storeDiagnostics(snapshot, o.URI(), orphanedSource, []*source.Diagnostic{diagnostic})
	}
}

func (s *Server) diagnosePkg(ctx context.Context, snapshot source.Snapshot, pkg source.Package, alwaysAnalyze bool) {
	ctx, done := event.Start(ctx, "Server.diagnosePkg", tag.Snapshot.Of(snapshot.ID()), tag.Package.Of(pkg.ID()))
	defer done()
	enableDiagnostics := false
	includeAnalysis := alwaysAnalyze // only run analyses for packages with open files
	for _, pgf := range pkg.CompiledGoFiles() {
		enableDiagnostics = enableDiagnostics || !snapshot.IgnoredFile(pgf.URI)
		includeAnalysis = includeAnalysis || snapshot.IsOpen(pgf.URI)
	}
	// Don't show any diagnostics on ignored files.
	if !enableDiagnostics {
		return
	}

	pkgDiagnostics, err := snapshot.DiagnosePackage(ctx, pkg)
	if err != nil {
		event.Error(ctx, "warning: diagnosing package", err, tag.Snapshot.Of(snapshot.ID()), tag.Package.Of(pkg.ID()))
		return
	}
	for _, cgf := range pkg.CompiledGoFiles() {
		s.storeDiagnostics(snapshot, cgf.URI, typeCheckSource, pkgDiagnostics[cgf.URI])
	}
	if includeAnalysis && !pkg.HasListOrParseErrors() {
		reports, err := source.Analyze(ctx, snapshot, pkg, false)
		if err != nil {
			event.Error(ctx, "warning: analyzing package", err, tag.Snapshot.Of(snapshot.ID()), tag.Package.Of(pkg.ID()))
			return
		}
		for _, cgf := range pkg.CompiledGoFiles() {
			s.storeDiagnostics(snapshot, cgf.URI, analysisSource, reports[cgf.URI])
		}
	}

	// If gc optimization details are requested, add them to the
	// diagnostic reports.
	s.gcOptimizationDetailsMu.Lock()
	_, enableGCDetails := s.gcOptimizationDetails[pkg.ID()]
	s.gcOptimizationDetailsMu.Unlock()
	if enableGCDetails {
		gcReports, err := source.GCOptimizationDetails(ctx, snapshot, pkg)
		if err != nil {
			event.Error(ctx, "warning: gc details", err, tag.Snapshot.Of(snapshot.ID()), tag.Package.Of(pkg.ID()))
		}
		s.gcOptimizationDetailsMu.Lock()
		_, enableGCDetails := s.gcOptimizationDetails[pkg.ID()]

		// NOTE(golang/go#44826): hold the gcOptimizationDetails lock, and re-check
		// whether gc optimization details are enabled, while storing gc_details
		// results. This ensures that the toggling of GC details and clearing of
		// diagnostics does not race with storing the results here.
		if enableGCDetails {
			for id, diags := range gcReports {
				fh := snapshot.FindFile(id.URI)
				// Don't publish gc details for unsaved buffers, since the underlying
				// logic operates on the file on disk.
				if fh == nil || !fh.Saved() {
					continue
				}
				s.storeDiagnostics(snapshot, id.URI, gcDetailsSource, diags)
			}
		}
		s.gcOptimizationDetailsMu.Unlock()
	}
}

// storeDiagnostics stores results from a single diagnostic source. If merge is
// true, it merges results into any existing results for this snapshot.
func (s *Server) storeDiagnostics(snapshot source.Snapshot, uri span.URI, dsource diagnosticSource, diags []*source.Diagnostic) {
	// Safeguard: ensure that the file actually exists in the snapshot
	// (see golang.org/issues/38602).
	fh := snapshot.FindFile(uri)
	if fh == nil {
		return
	}
	s.diagnosticsMu.Lock()
	defer s.diagnosticsMu.Unlock()
	if s.diagnostics[uri] == nil {
		s.diagnostics[uri] = &fileReports{
			publishedHash: hashDiagnostics(), // Hash for 0 diagnostics.
			reports:       map[diagnosticSource]diagnosticReport{},
		}
	}
	report := s.diagnostics[uri].reports[dsource]
	// Don't set obsolete diagnostics.
	if report.snapshotID > snapshot.ID() {
		return
	}
	if report.diags == nil || report.snapshotID != snapshot.ID() {
		report.diags = map[string]*source.Diagnostic{}
	}
	report.snapshotID = snapshot.ID()
	for _, d := range diags {
		report.diags[hashDiagnostics(d)] = d
	}
	s.diagnostics[uri].reports[dsource] = report
}

// clearDiagnosticSource clears all diagnostics for a given source type. It is
// necessary for cases where diagnostics have been invalidated by something
// other than a snapshot change, for example when gc_details is toggled.
func (s *Server) clearDiagnosticSource(dsource diagnosticSource) {
	s.diagnosticsMu.Lock()
	defer s.diagnosticsMu.Unlock()
	for _, reports := range s.diagnostics {
		delete(reports.reports, dsource)
	}
}

const WorkspaceLoadFailure = "Error loading workspace"

// showCriticalErrorStatus shows the error as a progress report.
// If the error is nil, it clears any existing error progress report.
func (s *Server) showCriticalErrorStatus(ctx context.Context, snapshot source.Snapshot, err *source.CriticalError) {
	s.criticalErrorStatusMu.Lock()
	defer s.criticalErrorStatusMu.Unlock()

	// Remove all newlines so that the error message can be formatted in a
	// status bar.
	var errMsg string
	if err != nil {
		event.Error(ctx, "errors loading workspace", err.MainError, tag.Snapshot.Of(snapshot.ID()), tag.Directory.Of(snapshot.View().Folder()))
		for _, d := range err.DiagList {
			s.storeDiagnostics(snapshot, d.URI, modSource, []*source.Diagnostic{d})
		}
		errMsg = strings.ReplaceAll(err.MainError.Error(), "\n", " ")
	}

	if s.criticalErrorStatus == nil {
		if errMsg != "" {
			s.criticalErrorStatus = s.progress.Start(ctx, WorkspaceLoadFailure, errMsg, nil, nil)
		}
		return
	}

	// If an error is already shown to the user, update it or mark it as
	// resolved.
	if errMsg == "" {
		s.criticalErrorStatus.End("Done.")
		s.criticalErrorStatus = nil
	} else {
		s.criticalErrorStatus.Report(errMsg, 0)
	}
}

// checkForOrphanedFile checks that the given URIs can be mapped to packages.
// If they cannot and the workspace is not otherwise unloaded, it also surfaces
// a warning, suggesting that the user check the file for build tags.
func (s *Server) checkForOrphanedFile(ctx context.Context, snapshot source.Snapshot, fh source.VersionedFileHandle) *source.Diagnostic {
	if fh.Kind() != source.Go {
		return nil
	}
	// builtin files won't have a package, but they are never orphaned.
	if snapshot.IsBuiltin(ctx, fh.URI()) {
		return nil
	}
	pkgs, err := snapshot.PackagesForFile(ctx, fh.URI(), source.TypecheckWorkspace, false)
	if len(pkgs) > 0 || err == nil {
		return nil
	}
	pgf, err := snapshot.ParseGo(ctx, fh, source.ParseHeader)
	if err != nil {
		return nil
	}
	spn, err := span.NewRange(snapshot.FileSet(), pgf.File.Name.Pos(), pgf.File.Name.End()).Span()
	if err != nil {
		return nil
	}
	rng, err := pgf.Mapper.Range(spn)
	if err != nil {
		return nil
	}
	// If the file no longer has a name ending in .go, this diagnostic is wrong
	if filepath.Ext(fh.URI().Filename()) != ".go" {
		return nil
	}
	// TODO(rstambler): We should be able to parse the build tags in the
	// file and show a more specific error message. For now, put the diagnostic
	// on the package declaration.
	return &source.Diagnostic{
		URI:      fh.URI(),
		Range:    rng,
		Severity: protocol.SeverityWarning,
		Source:   source.ListError,
		Message: fmt.Sprintf(`No packages found for open file %s: %v.
If this file contains build tags, try adding "-tags=<build tag>" to your gopls "buildFlags" configuration (see (https://github.com/golang/tools/blob/master/gopls/doc/settings.md#buildflags-string).
Otherwise, see the troubleshooting guidelines for help investigating (https://github.com/golang/tools/blob/master/gopls/doc/troubleshooting.md).
`, fh.URI().Filename(), err),
	}
}

// publishDiagnostics collects and publishes any unpublished diagnostic reports.
func (s *Server) publishDiagnostics(ctx context.Context, final bool, snapshot source.Snapshot) {
	ctx, done := event.Start(ctx, "Server.publishDiagnostics", tag.Snapshot.Of(snapshot.ID()))
	defer done()
	s.diagnosticsMu.Lock()
	defer s.diagnosticsMu.Unlock()

	published := 0
	defer func() {
		log.Trace.Logf(ctx, "published %d diagnostics", published)
	}()

	for uri, r := range s.diagnostics {
		// Snapshot IDs are always increasing, so we use them instead of file
		// versions to create the correct order for diagnostics.

		// If we've already delivered diagnostics for a future snapshot for this
		// file, do not deliver them.
		if r.snapshotID > snapshot.ID() {
			continue
		}
		anyReportsChanged := false
		reportHashes := map[diagnosticSource]string{}
		var diags []*source.Diagnostic
		for dsource, report := range r.reports {
			if report.snapshotID != snapshot.ID() {
				continue
			}
			var reportDiags []*source.Diagnostic
			for _, d := range report.diags {
				diags = append(diags, d)
				reportDiags = append(reportDiags, d)
			}
			hash := hashDiagnostics(reportDiags...)
			if hash != report.publishedHash {
				anyReportsChanged = true
			}
			reportHashes[dsource] = hash
		}

		if !final && !anyReportsChanged {
			// Don't invalidate existing reports on the client if we haven't got any
			// new information.
			continue
		}
		source.SortDiagnostics(diags)
		hash := hashDiagnostics(diags...)
		if hash == r.publishedHash {
			// Update snapshotID to be the latest snapshot for which this diagnostic
			// hash is valid.
			r.snapshotID = snapshot.ID()
			continue
		}
		var version int32
		if fh := snapshot.FindFile(uri); fh != nil { // file may have been deleted
			version = fh.Version()
		}
		if err := s.client.PublishDiagnostics(ctx, &protocol.PublishDiagnosticsParams{
			Diagnostics: toProtocolDiagnostics(diags),
			URI:         protocol.URIFromSpanURI(uri),
			Version:     version,
		}); err == nil {
			published++
			r.publishedHash = hash
			r.snapshotID = snapshot.ID()
			for dsource, hash := range reportHashes {
				report := r.reports[dsource]
				report.publishedHash = hash
				r.reports[dsource] = report
			}
		} else {
			if ctx.Err() != nil {
				// Publish may have failed due to a cancelled context.
				log.Trace.Log(ctx, "publish cancelled")
				return
			}
			event.Error(ctx, "publishReports: failed to deliver diagnostic", err, tag.URI.Of(uri))
		}
	}
}

func toProtocolDiagnostics(diagnostics []*source.Diagnostic) []protocol.Diagnostic {
	reports := []protocol.Diagnostic{}
	for _, diag := range diagnostics {
		related := make([]protocol.DiagnosticRelatedInformation, 0, len(diag.Related))
		for _, rel := range diag.Related {
			related = append(related, protocol.DiagnosticRelatedInformation{
				Location: protocol.Location{
					URI:   protocol.URIFromSpanURI(rel.URI),
					Range: rel.Range,
				},
				Message: rel.Message,
			})
		}
		pdiag := protocol.Diagnostic{
			// diag.Message might start with \n or \t
			Message:            strings.TrimSpace(diag.Message),
			Range:              diag.Range,
			Severity:           diag.Severity,
			Source:             string(diag.Source),
			Tags:               diag.Tags,
			RelatedInformation: related,
		}
		if diag.Code != "" {
			pdiag.Code = diag.Code
		}
		if diag.CodeHref != "" {
			pdiag.CodeDescription = &protocol.CodeDescription{Href: diag.CodeHref}
		}
		reports = append(reports, pdiag)
	}
	return reports
}

func (s *Server) shouldIgnoreError(ctx context.Context, snapshot source.Snapshot, err error) bool {
	if err == nil { // if there is no error at all
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	// If the folder has no Go code in it, we shouldn't spam the user with a warning.
	var hasGo bool
	_ = filepath.Walk(snapshot.View().Folder().Filename(), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !strings.HasSuffix(info.Name(), ".go") {
			return nil
		}
		hasGo = true
		return errors.New("done")
	})
	return !hasGo
}

// Diagnostics formattedfor the debug server
// (all the relevant fields of Server are private)
// (The alternative is to export them)
func (s *Server) Diagnostics() map[string][]string {
	ans := make(map[string][]string)
	s.diagnosticsMu.Lock()
	defer s.diagnosticsMu.Unlock()
	for k, v := range s.diagnostics {
		fn := k.Filename()
		for typ, d := range v.reports {
			if len(d.diags) == 0 {
				continue
			}
			for _, dx := range d.diags {
				ans[fn] = append(ans[fn], auxStr(dx, d, typ))
			}
		}
	}
	return ans
}

func auxStr(v *source.Diagnostic, d diagnosticReport, typ diagnosticSource) string {
	// Tags? RelatedInformation?
	msg := fmt.Sprintf("(%s)%q(source:%q,code:%q,severity:%s,snapshot:%d,type:%s)",
		v.Range, v.Message, v.Source, v.Code, v.Severity, d.snapshotID, typ)
	for _, r := range v.Related {
		msg += fmt.Sprintf(" [%s:%s,%q]", r.URI.Filename(), r.Range, r.Message)
	}
	return msg
}
