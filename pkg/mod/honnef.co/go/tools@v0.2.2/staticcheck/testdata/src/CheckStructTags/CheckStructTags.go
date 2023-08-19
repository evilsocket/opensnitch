package pkg

import (
	"encoding/xml"

	_ "github.com/jessevdk/go-flags"
)

type T1 struct {
	B int        `foo:"" foo:""` // want `duplicate struct tag`
	C int        `foo:"" bar:""`
	D int        `json:"-"`
	E int        `json:"\\"`                   // want `invalid JSON field name`
	F int        `json:",omitempty,omitempty"` // want `duplicate JSON option "omitempty"`
	G int        `json:",omitempty,string"`
	H int        `json:",string,omitempty,string"` // want `duplicate JSON option "string"`
	I int        `json:",unknown"`                 // want `unknown JSON option "unknown"`
	J int        `json:",string"`
	K *int       `json:",string"`
	L **int      `json:",string"` // want `the JSON string option`
	M complex128 `json:",string"` // want `the JSON string option`
	N int        `json:"some-name"`
	O int        `json:"some-name,inline"`
}

type T2 struct {
	A int `xml:",attr"`
	B int `xml:",chardata"`
	C int `xml:",cdata"`
	D int `xml:",innerxml"`
	E int `xml:",comment"`
	F int `xml:",omitempty"`
	G int `xml:",any"`
	H int `xml:",unknown"` // want `unknown option`
	I int `xml:",any,any"` // want `duplicate option`
	J int `xml:"a>b>c,"`
}

type T3 struct {
	A int `json:",omitempty" xml:",attr"`
	B int `json:",unknown" xml:",attr"` // want `unknown JSON option`
}

type T4 struct {
	A int   `choice:"foo" choice:"bar"`
	B []int `optional-value:"foo" optional-value:"bar"`
	C []int `default:"foo" default:"bar"`
	D int   `json:"foo" json:"bar"` // want `duplicate struct tag`
}

func xmlTags() {
	type T1 struct {
		A       int      `xml:",attr,innerxml"` // want `invalid combination of options: ",attr,innerxml"`
		XMLName xml.Name `xml:"ns "`            // want `namespace without name: "ns "`
		B       int      `xml:"a>"`             // want `trailing '>'`
		C       int      `xml:"a>b,attr"`       // want `a>b chain not valid with attr flag`
	}
	type T6 struct {
		XMLName xml.Name `xml:"foo"`
	}
	type T5 struct {
		F T6 `xml:"f"` // want `name "f" conflicts with name "foo" in CheckStructTags\.T6\.XMLName`
	}
}
