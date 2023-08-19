package pkg

import "reflect"

type wkt interface { // used
	XXX_WellKnownType() string // used
}

var typeOfWkt = reflect.TypeOf((*wkt)(nil)).Elem() // used

func Fn() { // used
	_ = typeOfWkt
}

type t *int // used

var _ t
