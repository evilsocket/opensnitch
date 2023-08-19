<div align="center">
	<h1><img alt="Staticcheck logo" src="/images/logo.svg" height="300" /><br />
		The advanced Go linter
	</h1>
</div>

Staticcheck is a state of the art linter for the [Go programming
language](https://go.dev/). Using static analysis, it finds bugs and performance issues,
offers simplifications, and enforces style rules.

**Financial support by [private and corporate sponsors](http://staticcheck.io/sponsors) guarantees the tool's continued development.
Please [become a sponsor](https://github.com/users/dominikh/sponsorship) if you or your company rely on Staticcheck.**


## Documentation

You can find extensive documentation on Staticcheck on [its website](https://staticcheck.io/docs/).

## Installation

### Releases

It is recommended that you run released versions of the tools. These
releases can be found as git tags (e.g. `2019.1`) as well as prebuilt
binaries in the [releases tab](https://github.com/dominikh/go-tools/releases).

The easiest way of using the releases from source is to use a Go
package manager such as Godep or Go modules. Alternatively you can use
a combination of `git clone -b` and `go get` to check out the
appropriate tag and download its dependencies.


### Master

You can also run the master branch instead of a release. Note that
while the master branch is usually stable, it may still contain new
checks or backwards incompatible changes that break your build. By
using the master branch you agree to become a beta tester.

## Tools

All of the following tools can be found in the cmd/ directory. Each
tool is accompanied by its own README, describing it in more detail.

| Tool                                               | Description                                                             |
|----------------------------------------------------|-------------------------------------------------------------------------|
| [keyify](cmd/keyify/)                              | Transforms an unkeyed struct literal into a keyed one.                  |
| [staticcheck](cmd/staticcheck/)                    | Go static analysis, detecting bugs, performance issues, and much more. |
| [structlayout](cmd/structlayout/)                  | Displays the layout (field sizes and padding) of structs.               |
| [structlayout-optimize](cmd/structlayout-optimize) | Reorders struct fields to minimize the amount of padding.               |
| [structlayout-pretty](cmd/structlayout-pretty)     | Formats the output of structlayout with ASCII art.                      |

## Libraries

In addition to the aforementioned tools, this repository contains the
libraries necessary to implement these tools.

Unless otherwise noted, none of these libraries have stable APIs.
Their main purpose is to aid the implementation of the tools. If you
decide to use these libraries, please vendor them and expect regular
backwards-incompatible changes.

## System requirements

We support the last two versions of Go.
