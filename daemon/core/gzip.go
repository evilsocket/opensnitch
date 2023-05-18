package core

import (
	"compress/gzip"
	"io/ioutil"
	"os"
)

// ReadGzipFile reads a gzip to text.
func ReadGzipFile(filename string) ([]byte, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	gz, err := gzip.NewReader(fd)
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	s, err := ioutil.ReadAll(gz)
	if err != nil {
		return nil, err
	}
	return s, nil
}
