#!/usr/bin/env sh
/home/dominikh/prj/src/honnef.co/go/tools/cmd/staticcheck/staticcheck -checks "all" -fail "" $1 &>/dev/null
exit 0
