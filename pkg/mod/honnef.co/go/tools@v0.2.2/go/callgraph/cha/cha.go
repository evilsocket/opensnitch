// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cha computes the call graph of a Go program using the Class
// Hierarchy Analysis (CHA) algorithm.
//
// CHA was first described in "Optimization of Object-Oriented Programs
// Using Static Class Hierarchy Analysis", Jeffrey Dean, David Grove,
// and Craig Chambers, ECOOP'95.
//
// CHA is related to RTA (see go/callgraph/rta); the difference is that
// CHA conservatively computes the entire "implements" relation between
// interfaces and concrete types ahead of time, whereas RTA uses dynamic
// programming to construct it on the fly as it encounters new functions
// reachable from main.  CHA may thus include spurious call edges for
// types that haven't been instantiated yet, or types that are never
// instantiated.
//
// Since CHA conservatively assumes that all functions are address-taken
// and all concrete types are put into interfaces, it is sound to run on
// partial programs, such as libraries without a main or test function.
//
package cha

import (
	"go/types"

	"honnef.co/go/tools/go/callgraph"
	"honnef.co/go/tools/go/ir"
	"honnef.co/go/tools/go/ir/irutil"
	"honnef.co/go/tools/go/types/typeutil"
)

// CallGraph computes the call graph of the specified program using the
// Class Hierarchy Analysis algorithm.
//
func CallGraph(prog *ir.Program) *callgraph.Graph {
	cg := callgraph.New(nil) // TODO(adonovan) eliminate concept of rooted callgraph

	allFuncs := irutil.AllFunctions(prog)

	// funcsBySig contains all functions, keyed by signature.  It is
	// the effective set of address-taken functions used to resolve
	// a dynamic call of a particular signature.
	var funcsBySig typeutil.Map // value is []*ir.Function

	// methodsByName contains all methods,
	// grouped by name for efficient lookup.
	methodsByName := make(map[string][]*ir.Function)

	// methodsMemo records, for every abstract method call call I.f on
	// interface type I, the set of concrete methods C.f of all
	// types C that satisfy interface I.
	methodsMemo := make(map[*types.Func][]*ir.Function)
	lookupMethods := func(m *types.Func) []*ir.Function {
		methods, ok := methodsMemo[m]
		if !ok {
			I := m.Type().(*types.Signature).Recv().Type().Underlying().(*types.Interface)
			for _, f := range methodsByName[m.Name()] {
				C := f.Signature.Recv().Type() // named or *named
				if types.Implements(C, I) {
					methods = append(methods, f)
				}
			}
			methodsMemo[m] = methods
		}
		return methods
	}

	for f := range allFuncs {
		if f.Signature.Recv() == nil {
			// Package initializers can never be address-taken.
			if f.Name() == "init" && f.Synthetic == ir.SyntheticPackageInitializer {
				continue
			}
			funcs, _ := funcsBySig.At(f.Signature).([]*ir.Function)
			funcs = append(funcs, f)
			funcsBySig.Set(f.Signature, funcs)
		} else {
			methodsByName[f.Name()] = append(methodsByName[f.Name()], f)
		}
	}

	addEdge := func(fnode *callgraph.Node, site ir.CallInstruction, g *ir.Function) {
		gnode := cg.CreateNode(g)
		callgraph.AddEdge(fnode, site, gnode)
	}

	addEdges := func(fnode *callgraph.Node, site ir.CallInstruction, callees []*ir.Function) {
		// Because every call to a highly polymorphic and
		// frequently used abstract method such as
		// (io.Writer).Write is assumed to call every concrete
		// Write method in the program, the call graph can
		// contain a lot of duplication.
		//
		// TODO(adonovan): opt: consider factoring the callgraph
		// API so that the Callers component of each edge is a
		// slice of nodes, not a singleton.
		for _, g := range callees {
			addEdge(fnode, site, g)
		}
	}

	for f := range allFuncs {
		fnode := cg.CreateNode(f)
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				if site, ok := instr.(ir.CallInstruction); ok {
					call := site.Common()
					if call.IsInvoke() {
						addEdges(fnode, site, lookupMethods(call.Method))
					} else if g := call.StaticCallee(); g != nil {
						addEdge(fnode, site, g)
					} else if _, ok := call.Value.(*ir.Builtin); !ok {
						callees, _ := funcsBySig.At(call.Signature()).([]*ir.Function)
						addEdges(fnode, site, callees)
					}
				}
			}
		}
	}

	return cg
}
