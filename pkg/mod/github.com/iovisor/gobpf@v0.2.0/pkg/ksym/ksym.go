package ksym

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
)

const (
	KALLSYMS = "/proc/kallsyms"
)

type ksymCache struct {
	sync.RWMutex
	ksym map[string]string
}

var cache ksymCache

// Ksym translates a kernel memory address into a kernel function name
// using `/proc/kallsyms`
func Ksym(addr string) (string, error) {
	if cache.ksym == nil {
		cache.ksym = make(map[string]string)
	}

	cache.Lock()
	defer cache.Unlock()

	if _, ok := cache.ksym[addr]; !ok {
		fd, err := os.Open(KALLSYMS)
		if err != nil {
			return "", err
		}
		defer fd.Close()

		fn := ksym(addr, fd)
		if fn == "" {
			return "", errors.New("kernel function not found for " + addr)
		}

		cache.ksym[addr] = fn
	}

	return cache.ksym[addr], nil
}

func ksym(addr string, r io.Reader) string {
	s := bufio.NewScanner(r)
	for s.Scan() {
		l := s.Text()
		ar := strings.Split(l, " ")
		if len(ar) != 3 {
			continue
		}

		if ar[0] == addr {
			return ar[2]
		}
	}

	return ""
}
