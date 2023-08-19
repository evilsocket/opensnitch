```GoSmith``` generates random, but legal, [Go programs](http://golang.org) to test Go compilers.

Bugs found to date:
  * [31 bugs](https://code.google.com/p/go/issues/list?can=1&q=label%3AGoSmith+-label%3ADocumentation+-status%3AInvalid&sort=-id&colspec=ID+Status+Stars+Release+Owner+Repo+Summary&cells=tiles) in gc compiler
  * [18 bugs](https://gcc.gnu.org/bugzilla/buglist.cgi?bug_status=UNCONFIRMED&bug_status=NEW&bug_status=ASSIGNED&bug_status=SUSPENDED&bug_status=WAITING&bug_status=REOPENED&bug_status=RESOLVED&bug_status=VERIFIED&bug_status=CLOSED&cf_known_to_fail_type=allwords&cf_known_to_work_type=allwords&f0=OP&f1=OP&f2=product&f3=component&f4=alias&f5=short_desc&f6=status_whiteboard&f7=content&f8=CP&f9=CP&j1=OR&list_id=97425&o2=substring&o3=substring&o4=substring&o5=substring&o6=substring&o7=matches&query_format=advanced&v2=GoSmith&v3=GoSmith&v4=GoSmith&v5=GoSmith&v6=GoSmith&v7=%22GoSmith%22) in gccgo compiler
  * [5 bugs](https://github.com/go-llvm/llgo/issues?labels=GoSmith) in llgo compiler (+[bug 1](https://github.com/go-llvm/llgo/issues/174), +[bug 2](https://github.com/go-llvm/llgo/issues/175), +[bug 3](https://github.com/go-llvm/llgo/issues/176), +[bug 4](https://github.com/go-llvm/llgo/issues/177))
  * [3 bugs](https://code.google.com/p/go/issues/list?can=1&q=label%3AGoSmith+label%3ADocumentation+-status%3AInvalid&sort=-id&colspec=ID+Status+Stars+Release+Owner+Repo+Summary&cells=tiles) in the spec were uncovered due to this work

Usage instructions:
```
# Bootstrap Go implementation:
./make.bash
GOARCH=386 go tool dist bootstrap
GOARCH=arm go tool dist bootstrap
GOARCH=386 go install std
GOARCH=arm go install std
go install -race -a std
go install -a std
# Download binaries:
go get -u code.google.com/p/gosmith/gosmith
go get -u code.google.com/p/go.tools/cmd/ssadump
# Test:
go run driver.go -checkers=amd64,386,arm,exec
```
