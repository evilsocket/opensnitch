// Package pkg ...
package pkg

import (
	"fmt" // want `package "fmt" is being imported more than once`
	fmt1 "fmt"
	fmt2 "fmt"

	fine "net/http"

	"os" // want `package "os" is being imported more than once`
	os1 "os"

	"C"
	_ "unsafe"
)

var _ = fmt.Println
var _ = fmt1.Println
var _ = fmt2.Println
var _ = fine.ListenAndServe
var _ = os.Getenv
var _ = os1.Getenv
