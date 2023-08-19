package pkg

// #include <stdlib.h>
import "C"
import "unsafe"

func fnCgo(arg C.size_t) {
	var ptr unsafe.Pointer
	C.realloc(ptr, arg)
}
