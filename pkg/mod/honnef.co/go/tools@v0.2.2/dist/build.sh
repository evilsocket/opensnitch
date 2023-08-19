#!/bin/sh -e


build() {
    ROOT="$GOPATH/src/honnef.co/go/tools"

    os="$1"
    arch="$2"

    echo "Building GOOS=$os GOARCH=$arch..."
    exe="staticcheck"
    if [ $os = "windows" ]; then
        exe="${exe}.exe"
    fi
    target="staticcheck_${os}_${arch}"

    arm=""
    case "$arch" in
        armv5l)
            arm=5
            arch=arm
            ;;
        armv6l)
            arm=6
            arch=arm
            ;;
        armv7l)
            arm=7
            arch=arm
            ;;
        arm64)
            arch=arm64
            ;;
    esac

    mkdir "$d/staticcheck"
    cp "$ROOT/LICENSE" "$ROOT/LICENSE-THIRD-PARTY" "$d/staticcheck"
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOARM=$arm GO111MODULE=on go build -trimpath -o "$d/staticcheck/$exe" honnef.co/go/tools/cmd/staticcheck
    (
        cd "$d"
        tar -czf "$target.tar.gz" staticcheck
        sha256sum "$target.tar.gz" > "$target.tar.gz.sha256"
    )
    rm -rf "$d/staticcheck"
}

rev="$1"
if [ -z "$rev" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi


mkdir "$rev"
d=$(realpath "$rev")

wrk=$(mktemp -d)
trap "{ rm -rf \"$wrk\"; }" EXIT
cd "$wrk"

go mod init foo
GO111MODULE=on go get -d honnef.co/go/tools/cmd/staticcheck@"$rev"


SYSTEMS=(windows linux freebsd)
ARCHS=(amd64 386)
for os in ${SYSTEMS[@]}; do
    for arch in ${ARCHS[@]}; do
        build "$os" "$arch"
    done
done

build "darwin" "amd64"

for arch in armv5l armv6l armv7l arm64; do
    build "linux" "$arch"
done

(
    cd "$d"
    sha256sum -c --strict *.sha256
)
