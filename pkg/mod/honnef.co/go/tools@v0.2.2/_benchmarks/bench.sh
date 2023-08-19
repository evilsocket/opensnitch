#!/usr/bin/env bash
set -e

declare -A PKGS=(
	["strconv"]="strconv"
	["net/http"]="net/http"
	["image/color"]="image/color"
	["std"]="std"
	["k8s"]="k8s.io/kubernetes/pkg/..."
)

MIN_CORES=32
MAX_CORES=32
INCR_CORES=2
MIN_GOGC=100
MAX_GOGC=100
SAMPLES=10
WIPE_CACHE=1
FORMAT=bench
BIN=$(realpath ./silent-staticcheck.sh)

runBenchmark() {
	local pkg="$1"
	local label="$2"
	local gc="$3"
	local cores="$4"
	local wipe="$5"

	if [ $wipe -ne 0 ]; then
		rm -rf ~/.cache/staticcheck
	fi

	local out=$(GOGC=$gc GOMAXPROCS=$cores env time -f "%e %M" $BIN $pkg 2>&1)
	local t=$(echo "$out" | cut -f1 -d" ")
	local m=$(echo "$out" | cut -f2 -d" ")
	local ns=$(printf "%s 1000000000 * p" $t | dc)
	local b=$((m * 1024))

	case $FORMAT in
		bench)
			printf "BenchmarkStaticcheck-%s-GOGC%d-wiped%d-%d  1   %.0f ns/op  %.0f B/op\n" "$label" "$gc" "$wipe" "$cores" "$ns" "$b"
			;;
		csv)
			printf "%s,%d,%d,%d,%.0f,%.0f\n" "$label" "$gc" "$cores" "$wipe" "$ns" "$b"
			;;
	esac
}

export GO111MODULE=off

if [ "$FORMAT" = "csv" ]; then
	printf "packages,gogc,gomaxprocs,wipe-cache,time,memory\n"
fi

for label in "${!PKGS[@]}"; do
	pkg=${PKGS[$label]}
	for gc in $(seq $MIN_GOGC 10 $MAX_GOGC); do
		for cores in $(seq $MIN_CORES $INCR_CORES $MAX_CORES); do
			for i in $(seq 1 $SAMPLES); do
				runBenchmark "$pkg" "$label" "$gc" "$cores" 1
				runBenchmark "$pkg" "$label" "$gc" "$cores" 0
			done
		done
	done
done
