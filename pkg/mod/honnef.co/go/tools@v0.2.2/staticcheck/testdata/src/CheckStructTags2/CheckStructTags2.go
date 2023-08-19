package pkg

type T5 struct {
	A int   `choice:"foo" choice:"bar"`                 // want `duplicate struct tag`
	B []int `optional-value:"foo" optional-value:"bar"` // want `duplicate struct tag`
	C []int `default:"foo" default:"bar"`               // want `duplicate struct tag`
}
