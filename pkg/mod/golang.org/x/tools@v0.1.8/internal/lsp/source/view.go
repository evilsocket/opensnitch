// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package source

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/scanner"
	"go/token"
	"go/types"
	"io"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/internal/gocommand"
	"golang.org/x/tools/internal/imports"
	"golang.org/x/tools/internal/lsp/progress"
	"golang.org/x/tools/internal/lsp/protocol"
	"golang.org/x/tools/internal/span"
	errors "golang.org/x/xerrors"
)

// Snapshot represents the current state for the given view.
type Snapshot interface {
	ID() uint64

	// View returns the View associated with this snapshot.
	View() View

	// BackgroundContext returns a context used for all background processing
	// on behalf of this snapshot.
	BackgroundContext() context.Context

	// Fileset returns the Fileset used to parse all the Go files in this snapshot.
	FileSet() *token.FileSet

	// ValidBuildConfiguration returns true if there is some error in the
	// user's workspace. In particular, if they are both outside of a module
	// and their GOPATH.
	ValidBuildConfiguration() bool

	// WriteEnv writes the view-specific environment to the io.Writer.
	WriteEnv(ctx context.Context, w io.Writer) error

	// FindFile returns the FileHandle for the given URI, if it is already
	// in the given snapshot.
	FindFile(uri span.URI) VersionedFileHandle

	// GetVersionedFile returns the VersionedFileHandle for a given URI,
	// initializing it if it is not already part of the snapshot.
	GetVersionedFile(ctx context.Context, uri span.URI) (VersionedFileHandle, error)

	// GetFile returns the FileHandle for a given URI, initializing it if it is
	// not already part of the snapshot.
	GetFile(ctx context.Context, uri span.URI) (FileHandle, error)

	// AwaitInitialized waits until the snapshot's view is initialized.
	AwaitInitialized(ctx context.Context)

	// IsOpen returns whether the editor currently has a file open.
	IsOpen(uri span.URI) bool

	// IgnoredFile reports if a file would be ignored by a `go list` of the whole
	// workspace.
	IgnoredFile(uri span.URI) bool

	// Templates returns the .tmpl files
	Templates() map[span.URI]VersionedFileHandle

	// ParseGo returns the parsed AST for the file.
	// If the file is not available, returns nil and an error.
	ParseGo(ctx context.Context, fh FileHandle, mode ParseMode) (*ParsedGoFile, error)

	// PosToField is a cache of *ast.Fields by token.Pos. This allows us
	// to quickly find corresponding *ast.Field node given a *types.Var.
	// We must refer to the AST to render type aliases properly when
	// formatting signatures and other types.
	PosToField(ctx context.Context, pkg Package, pos token.Pos) (*ast.Field, error)

	// PosToDecl maps certain objects' positions to their surrounding
	// ast.Decl. This mapping is used when building the documentation
	// string for the objects.
	PosToDecl(ctx context.Context, pkg Package, pos token.Pos) (ast.Decl, error)

	// DiagnosePackage returns basic diagnostics, including list, parse, and type errors
	// for pkg, grouped by file.
	DiagnosePackage(ctx context.Context, pkg Package) (map[span.URI][]*Diagnostic, error)

	// Analyze runs the analyses for the given package at this snapshot.
	Analyze(ctx context.Context, pkgID string, analyzers []*Analyzer) ([]*Diagnostic, error)

	// RunGoCommandPiped runs the given `go` command, writing its output
	// to stdout and stderr. Verb, Args, and WorkingDir must be specified.
	RunGoCommandPiped(ctx context.Context, mode InvocationFlags, inv *gocommand.Invocation, stdout, stderr io.Writer) error

	// RunGoCommandDirect runs the given `go` command. Verb, Args, and
	// WorkingDir must be specified.
	RunGoCommandDirect(ctx context.Context, mode InvocationFlags, inv *gocommand.Invocation) (*bytes.Buffer, error)

	// RunGoCommands runs a series of `go` commands that updates the go.mod
	// and go.sum file for wd, and returns their updated contents.
	RunGoCommands(ctx context.Context, allowNetwork bool, wd string, run func(invoke func(...string) (*bytes.Buffer, error)) error) (bool, []byte, []byte, error)

	// RunProcessEnvFunc runs fn with the process env for this snapshot's view.
	// Note: the process env contains cached module and filesystem state.
	RunProcessEnvFunc(ctx context.Context, fn func(*imports.Options) error) error

	// ModFiles are the go.mod files enclosed in the snapshot's view and known
	// to the snapshot.
	ModFiles() []span.URI

	// ParseMod is used to parse go.mod files.
	ParseMod(ctx context.Context, fh FileHandle) (*ParsedModule, error)

	// ModWhy returns the results of `go mod why` for the module specified by
	// the given go.mod file.
	ModWhy(ctx context.Context, fh FileHandle) (map[string]string, error)

	// ModTidy returns the results of `go mod tidy` for the module specified by
	// the given go.mod file.
	ModTidy(ctx context.Context, pm *ParsedModule) (*TidiedModule, error)

	// GoModForFile returns the URI of the go.mod file for the given URI.
	GoModForFile(uri span.URI) span.URI

	// BuiltinFile returns information about the special builtin package.
	BuiltinFile(ctx context.Context) (*ParsedGoFile, error)

	// IsBuiltin reports whether uri is part of the builtin package.
	IsBuiltin(ctx context.Context, uri span.URI) bool

	// PackagesForFile returns the packages that this file belongs to, checked
	// in mode.
	PackagesForFile(ctx context.Context, uri span.URI, mode TypecheckMode, includeTestVariants bool) ([]Package, error)

	// PackageForFile returns a single package that this file belongs to,
	// checked in mode and filtered by the package policy.
	PackageForFile(ctx context.Context, uri span.URI, mode TypecheckMode, selectPackage PackageFilter) (Package, error)

	// GetActiveReverseDeps returns the active files belonging to the reverse
	// dependencies of this file's package, checked in TypecheckWorkspace mode.
	GetReverseDependencies(ctx context.Context, id string) ([]Package, error)

	// CachedImportPaths returns all the imported packages loaded in this
	// snapshot, indexed by their import path and checked in TypecheckWorkspace
	// mode.
	CachedImportPaths(ctx context.Context) (map[string]Package, error)

	// KnownPackages returns all the packages loaded in this snapshot, checked
	// in TypecheckWorkspace mode.
	KnownPackages(ctx context.Context) ([]Package, error)

	// ActivePackages returns the packages considered 'active' in the workspace.
	//
	// In normal memory mode, this is all workspace packages. In degraded memory
	// mode, this is just the reverse transitive closure of open packages.
	ActivePackages(ctx context.Context) ([]Package, error)

	// Symbols returns all symbols in the snapshot.
	Symbols(ctx context.Context) (map[span.URI][]Symbol, error)

	// Metadata returns package metadata associated with the given file URI.
	MetadataForFile(ctx context.Context, uri span.URI) ([]Metadata, error)

	// GetCriticalError returns any critical errors in the workspace.
	GetCriticalError(ctx context.Context) *CriticalError

	// BuildGoplsMod generates a go.mod file for all modules in the workspace.
	// It bypasses any existing gopls.mod.
	BuildGoplsMod(ctx context.Context) (*modfile.File, error)
}

// PackageFilter sets how a package is filtered out from a set of packages
// containing a given file.
type PackageFilter int

const (
	// NarrowestPackage picks the "narrowest" package for a given file.
	// By "narrowest" package, we mean the package with the fewest number of
	// files that includes the given file. This solves the problem of test
	// variants, as the test will have more files than the non-test package.
	NarrowestPackage PackageFilter = iota

	// WidestPackage returns the Package containing the most files.
	// This is useful for something like diagnostics, where we'd prefer to
	// offer diagnostics for as many files as possible.
	WidestPackage
)

// InvocationFlags represents the settings of a particular go command invocation.
// It is a mode, plus a set of flag bits.
type InvocationFlags int

const (
	// Normal is appropriate for commands that might be run by a user and don't
	// deliberately modify go.mod files, e.g. `go test`.
	Normal InvocationFlags = iota
	// UpdateUserModFile is for commands that intend to update the user's real
	// go.mod file, e.g. `go mod tidy` in response to a user's request to tidy.
	UpdateUserModFile
	// WriteTemporaryModFile is for commands that need information from a
	// modified version of the user's go.mod file, e.g. `go mod tidy` used to
	// generate diagnostics.
	WriteTemporaryModFile
	// LoadWorkspace is for packages.Load, and other operations that should
	// consider the whole workspace at once.
	LoadWorkspace

	// AllowNetwork is a flag bit that indicates the invocation should be
	// allowed to access the network.
	AllowNetwork InvocationFlags = 1 << 10
)

func (m InvocationFlags) Mode() InvocationFlags {
	return m & (AllowNetwork - 1)
}

func (m InvocationFlags) AllowNetwork() bool {
	return m&AllowNetwork != 0
}

// View represents a single workspace.
// This is the level at which we maintain configuration like working directory
// and build tags.
type View interface {
	// Name returns the name this view was constructed with.
	Name() string

	// Folder returns the folder with which this view was created.
	Folder() span.URI

	// TempWorkspace returns the folder this view uses for its temporary
	// workspace module.
	TempWorkspace() span.URI

	// Shutdown closes this view, and detaches it from its session.
	Shutdown(ctx context.Context)

	// Options returns a copy of the Options for this view.
	Options() *Options

	// SetOptions sets the options of this view to new values.
	// Calling this may cause the view to be invalidated and a replacement view
	// added to the session. If so the new view will be returned, otherwise the
	// original one will be.
	SetOptions(context.Context, *Options) (View, error)

	// Snapshot returns the current snapshot for the view.
	Snapshot(ctx context.Context) (Snapshot, func())

	// Rebuild rebuilds the current view, replacing the original view in its session.
	Rebuild(ctx context.Context) (Snapshot, func(), error)

	// IsGoPrivatePath reports whether target is a private import path, as identified
	// by the GOPRIVATE environment variable.
	IsGoPrivatePath(path string) bool

	// ModuleUpgrades returns known module upgrades.
	ModuleUpgrades() map[string]string

	// RegisterModuleUpgrades registers that upgrades exist for the given modules.
	RegisterModuleUpgrades(upgrades map[string]string)
}

// A FileSource maps uris to FileHandles. This abstraction exists both for
// testability, and so that algorithms can be run equally on session and
// snapshot files.
type FileSource interface {
	// GetFile returns the FileHandle for a given URI.
	GetFile(ctx context.Context, uri span.URI) (FileHandle, error)
}

// A ParsedGoFile contains the results of parsing a Go file.
type ParsedGoFile struct {
	URI  span.URI
	Mode ParseMode
	File *ast.File
	Tok  *token.File
	// Source code used to build the AST. It may be different from the
	// actual content of the file if we have fixed the AST.
	Src      []byte
	Mapper   *protocol.ColumnMapper
	ParseErr scanner.ErrorList
}

// A ParsedModule contains the results of parsing a go.mod file.
type ParsedModule struct {
	URI         span.URI
	File        *modfile.File
	Mapper      *protocol.ColumnMapper
	ParseErrors []*Diagnostic
}

// A TidiedModule contains the results of running `go mod tidy` on a module.
type TidiedModule struct {
	// Diagnostics representing changes made by `go mod tidy`.
	Diagnostics []*Diagnostic
	// The bytes of the go.mod file after it was tidied.
	TidiedContent []byte
}

// Metadata represents package metadata retrieved from go/packages.
type Metadata interface {
	// PackageName is the package name.
	PackageName() string

	// PackagePath is the package path.
	PackagePath() string
}

// Session represents a single connection from a client.
// This is the level at which things like open files are maintained on behalf
// of the client.
// A session may have many active views at any given time.
type Session interface {
	// ID returns the unique identifier for this session on this server.
	ID() string
	// NewView creates a new View, returning it and its first snapshot. If a
	// non-empty tempWorkspace directory is provided, the View will record a copy
	// of its gopls workspace module in that directory, so that client tooling
	// can execute in the same main module.
	NewView(ctx context.Context, name string, folder, tempWorkspace span.URI, options *Options) (View, Snapshot, func(), error)

	// Cache returns the cache that created this session, for debugging only.
	Cache() interface{}

	// View returns a view with a matching name, if the session has one.
	View(name string) View

	// ViewOf returns a view corresponding to the given URI.
	ViewOf(uri span.URI) (View, error)

	// Views returns the set of active views built by this session.
	Views() []View

	// Shutdown the session and all views it has created.
	Shutdown(ctx context.Context)

	// GetFile returns a handle for the specified file.
	GetFile(ctx context.Context, uri span.URI) (FileHandle, error)

	// DidModifyFile reports a file modification to the session. It returns
	// the new snapshots after the modifications have been applied, paired with
	// the affected file URIs for those snapshots.
	DidModifyFiles(ctx context.Context, changes []FileModification) (map[Snapshot][]span.URI, []func(), error)

	// ExpandModificationsToDirectories returns the set of changes with the
	// directory changes removed and expanded to include all of the files in
	// the directory.
	ExpandModificationsToDirectories(ctx context.Context, changes []FileModification) []FileModification

	// Overlays returns a slice of file overlays for the session.
	Overlays() []Overlay

	// Options returns a copy of the SessionOptions for this session.
	Options() *Options

	// SetOptions sets the options of this session to new values.
	SetOptions(*Options)

	// FileWatchingGlobPatterns returns glob patterns to watch every directory
	// known by the view. For views within a module, this is the module root,
	// any directory in the module root, and any replace targets.
	FileWatchingGlobPatterns(ctx context.Context) map[string]struct{}

	// SetProgressTracker sets the progress tracker for the session.
	SetProgressTracker(tracker *progress.Tracker)
}

var ErrViewExists = errors.New("view already exists for session")

// Overlay is the type for a file held in memory on a session.
type Overlay interface {
	VersionedFileHandle
}

// FileModification represents a modification to a file.
type FileModification struct {
	URI    span.URI
	Action FileAction

	// OnDisk is true if a watched file is changed on disk.
	// If true, Version will be -1 and Text will be nil.
	OnDisk bool

	// Version will be -1 and Text will be nil when they are not supplied,
	// specifically on textDocument/didClose and for on-disk changes.
	Version int32
	Text    []byte

	// LanguageID is only sent from the language client on textDocument/didOpen.
	LanguageID string
}

type FileAction int

const (
	UnknownFileAction = FileAction(iota)
	Open
	Change
	Close
	Save
	Create
	Delete
	InvalidateMetadata
)

func (a FileAction) String() string {
	switch a {
	case Open:
		return "Open"
	case Change:
		return "Change"
	case Close:
		return "Close"
	case Save:
		return "Save"
	case Create:
		return "Create"
	case Delete:
		return "Delete"
	case InvalidateMetadata:
		return "InvalidateMetadata"
	default:
		return "Unknown"
	}
}

var ErrTmpModfileUnsupported = errors.New("-modfile is unsupported for this Go version")
var ErrNoModOnDisk = errors.New("go.mod file is not on disk")

func IsNonFatalGoModError(err error) bool {
	return err == ErrTmpModfileUnsupported || err == ErrNoModOnDisk
}

// ParseMode controls the content of the AST produced when parsing a source file.
type ParseMode int

const (
	// ParseHeader specifies that the main package declaration and imports are needed.
	// This is the mode used when attempting to examine the package graph structure.
	ParseHeader ParseMode = iota

	// ParseExported specifies that the package is used only as a dependency,
	// and only its exported declarations are needed. More may be included if
	// necessary to avoid type errors.
	ParseExported

	// ParseFull specifies the full AST is needed.
	// This is used for files of direct interest where the entire contents must
	// be considered.
	ParseFull
)

// TypecheckMode controls what kind of parsing should be done (see ParseMode)
// while type checking a package.
type TypecheckMode int

const (
	// Invalid default value.
	TypecheckUnknown TypecheckMode = iota
	// TypecheckFull means to use ParseFull.
	TypecheckFull
	// TypecheckWorkspace means to use ParseFull for workspace packages, and
	// ParseExported for others.
	TypecheckWorkspace
	// TypecheckAll means ParseFull for workspace packages, and both Full and
	// Exported for others. Only valid for some functions.
	TypecheckAll
)

type VersionedFileHandle interface {
	FileHandle
	Version() int32
	Session() string

	// LSPIdentity returns the version identity of a file.
	VersionedFileIdentity() VersionedFileIdentity
}

type VersionedFileIdentity struct {
	URI span.URI

	// SessionID is the ID of the LSP session.
	SessionID string

	// Version is the version of the file, as specified by the client. It should
	// only be set in combination with SessionID.
	Version int32
}

// FileHandle represents a handle to a specific version of a single file.
type FileHandle interface {
	URI() span.URI
	Kind() FileKind

	// FileIdentity returns a FileIdentity for the file, even if there was an
	// error reading it.
	FileIdentity() FileIdentity
	// Read reads the contents of a file.
	// If the file is not available, returns a nil slice and an error.
	Read() ([]byte, error)
	// Saved reports whether the file has the same content on disk.
	Saved() bool
}

// FileIdentity uniquely identifies a file at a version from a FileSystem.
type FileIdentity struct {
	URI span.URI

	// Identifier represents a unique identifier for the file's content.
	Hash string

	// Kind is the file's kind.
	Kind FileKind
}

func (id FileIdentity) String() string {
	return fmt.Sprintf("%s%s%s", id.URI, id.Hash, id.Kind)
}

// FileKind describes the kind of the file in question.
// It can be one of Go, mod, or sum.
type FileKind int

const (
	// UnknownKind is a file type we don't know about.
	UnknownKind = FileKind(iota)

	// Go is a normal go source file.
	Go
	// Mod is a go.mod file.
	Mod
	// Sum is a go.sum file.
	Sum
	// Tmpl is a template file.
	Tmpl
)

// Analyzer represents a go/analysis analyzer with some boolean properties
// that let the user know how to use the analyzer.
type Analyzer struct {
	Analyzer *analysis.Analyzer

	// Enabled reports whether the analyzer is enabled. This value can be
	// configured per-analysis in user settings. For staticcheck analyzers,
	// the value of the Staticcheck setting overrides this field.
	Enabled bool

	// Fix is the name of the suggested fix name used to invoke the suggested
	// fixes for the analyzer. It is non-empty if we expect this analyzer to
	// provide its fix separately from its diagnostics. That is, we should apply
	// the analyzer's suggested fixes through a Command, not a TextEdit.
	Fix string

	// ActionKind is the kind of code action this analyzer produces. If
	// unspecified the type defaults to quickfix.
	ActionKind []protocol.CodeActionKind

	// Severity is the severity set for diagnostics reported by this
	// analyzer. If left unset it defaults to Warning.
	Severity protocol.DiagnosticSeverity
}

func (a Analyzer) IsEnabled(view View) bool {
	// Staticcheck analyzers can only be enabled when staticcheck is on.
	if _, ok := view.Options().StaticcheckAnalyzers[a.Analyzer.Name]; ok {
		if !view.Options().Staticcheck {
			return false
		}
	}
	if enabled, ok := view.Options().Analyses[a.Analyzer.Name]; ok {
		return enabled
	}
	return a.Enabled
}

// Package represents a Go package that has been type-checked. It maintains
// only the relevant fields of a *go/packages.Package.
type Package interface {
	ID() string
	Name() string
	PkgPath() string
	CompiledGoFiles() []*ParsedGoFile
	File(uri span.URI) (*ParsedGoFile, error)
	GetSyntax() []*ast.File
	GetTypes() *types.Package
	GetTypesInfo() *types.Info
	GetTypesSizes() types.Sizes
	IsIllTyped() bool
	ForTest() string
	GetImport(pkgPath string) (Package, error)
	MissingDependencies() []string
	Imports() []Package
	Version() *module.Version
	HasListOrParseErrors() bool
	HasTypeErrors() bool
	ParseMode() ParseMode
}

type CriticalError struct {
	// MainError is the primary error. Must be non-nil.
	MainError error
	// DiagList contains any supplemental (structured) diagnostics.
	DiagList []*Diagnostic
}

// An Diagnostic corresponds to an LSP Diagnostic.
// https://microsoft.github.io/language-server-protocol/specification#diagnostic
type Diagnostic struct {
	URI      span.URI
	Range    protocol.Range
	Severity protocol.DiagnosticSeverity
	Code     string
	CodeHref string

	// Source is a human-readable description of the source of the error.
	// Diagnostics generated by an analysis.Analyzer set it to Analyzer.Name.
	Source DiagnosticSource

	Message string

	Tags    []protocol.DiagnosticTag
	Related []RelatedInformation

	// Fields below are used internally to generate quick fixes. They aren't
	// part of the LSP spec and don't leave the server.
	SuggestedFixes []SuggestedFix
	Analyzer       *Analyzer
}

type DiagnosticSource string

const (
	UnknownError             DiagnosticSource = "<Unknown source>"
	ListError                DiagnosticSource = "go list"
	ParseError               DiagnosticSource = "syntax"
	TypeError                DiagnosticSource = "compiler"
	ModTidyError             DiagnosticSource = "go mod tidy"
	OptimizationDetailsError DiagnosticSource = "optimizer details"
	UpgradeNotification      DiagnosticSource = "upgrade available"
)

func AnalyzerErrorKind(name string) DiagnosticSource {
	return DiagnosticSource(name)
}

var (
	PackagesLoadError = errors.New("packages.Load error")
)

// WorkspaceModuleVersion is the nonexistent pseudoversion suffix used in the
// construction of the workspace module. It is exported so that we can make
// sure not to show this version to end users in error messages, to avoid
// confusion.
// The major version is not included, as that depends on the module path.
//
// If workspace module A is dependent on workspace module B, we need our
// nonexistant version to be greater than the version A mentions.
// Otherwise, the go command will try to update to that version. Use a very
// high minor version to make that more likely.
const workspaceModuleVersion = ".9999999.0-goplsworkspace"

func IsWorkspaceModuleVersion(version string) bool {
	return strings.HasSuffix(version, workspaceModuleVersion)
}

func WorkspaceModuleVersion(majorVersion string) string {
	// Use the highest compatible major version to avoid unwanted upgrades.
	// See the comment on workspaceModuleVersion.
	if majorVersion == "v0" {
		majorVersion = "v1"
	}
	return majorVersion + workspaceModuleVersion
}
