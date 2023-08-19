# Generate Go types and signatures for the LSP protocol

## Setup

Make sure `node` and `tsc` are installed and in your PATH. There are detailed instructions below.
(`tsc -v` should be at least `4.2.4`.)
Get the typescript code for the jsonrpc protocol with

`git clone git@github.com:microsoft vscode-languageserver-node.git` or
`git clone https://github.com/microsoft/vscode-languageserver-node.git`

`util.ts` expects it to be in your HOME directory

If you want to reproduce the existing files you need to be on a branch with the same git hash that `util.ts` expects, for instance, `git checkout 7b90c29`

## Usage

Code is generated and normalized by

`tsc && node code.js && gofmt -w ts*.go`

(`code.ts` imports `util.ts`.) This generates 3 files in the current directory, `tsprotocol.go`
containing type definitions, and `tsserver.go`, `tsclient.go` containing API stubs.

## Notes

1. `code.ts` and `util.ts` use the Typescript compiler's API, which is [introduced](https://github.com/Microsoft/TypeScript/wiki/Architectural-Overview) in their wiki.
2. Because the Typescript and Go type systems are incompatible, `code.ts` and `util.ts` are filled with heuristics and special cases. Therefore they are tied to a specific commit of `vscode-languageserver-node`. The hash code of the commit is included in the header of
the generated files and stored in the variable `gitHash` in `go.ts`. It is checked (see `git()` in `util.ts`) on every execution.
3. Generating the `ts*.go` files is only semi-automated. Please file an issue if the released version is too far behind.
4. For the impatient, first change `gitHash` by hand (`git()` shows how to find the hash).
    1. Then try to run `code.ts`. This will likely fail because the heuristics don't cover some new case. For instance, some simple type like `string` might have changed to a union type `string | [number,number]`. Another example is that some generated formal parameter may have anonymous structure type, which is essentially unusable.
    2. Next step is to move the generated code to `internal/lsp/protocol` and try to build `gopls` and its tests. This will likely fail because types have changed. Generally the fixes are fairly easy. Then run all the tests.
    3. Since there are not adequate integration tests, the next step is to run `gopls`.

## Detailed instructions for installing node and typescript

(The instructions are somewhat different for  Linux and MacOS. They install some things locally, so `$PATH` needs to be changed.)

1. For Linux, it is possible to build node from scratch, but if there's a package manager, that's simpler.
    1. To use the Ubuntu package manager
        1. `sudo apt update` (if you can't `sudo` then these instructions are not helpful)
        2. `sudo apt install nodejs` (this may install `/usr/bin/nodejs` rather than `/usr/bin/node`. For me, `/usr/bin/nodejs` pointed to an actual executable `/etc/alternatives/nodejs`, which should be copied to `/usr/bin/node`)
        3. `sudo apt intall npm`
    1. To build from scratch
        1. Go to the [node site](https://nodejs.org), and download the one recommended for most users, and then you're on your own. (It's got binaries in it. Untar the file somewhere and put its `bin` directory in your path, perhaps?)
2. The Mac is easier. Download the macOS installer from [nodejs](https://nodejs.org), click on it, and let it install.
3. (There's a good chance that soon you will be asked to upgrade your new npm. `sudo npm install -g npm` is the command.)
4. For either system, node and nvm should now be available. Running `node -v` and `npm -v` should produce version numbers.
5. `npm install typescript`
    1. This may give warning messages that indicate you've failed to set up a project. Ignore them.
    2. Your home directory will now have new directories `.npm` and `node_modules` (and a `package_lock.json` file)
    3. The typescript executable `tsc` will be in `node_modules/.bin`, so put that directory in your path.
    4. `tsc -v` should print "Version 4.2.4" (or later). If not you may (as I did) have an obsolete tsc earlier in your path.
6. `npm install @types/node` (Without this there will be many incomprehensible typescript error messages.)
