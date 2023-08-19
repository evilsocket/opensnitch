package toml

import (
	"fmt"
	"testing"
	"time"
)

func TestEncode(t *testing.T) {
	type Embedded struct {
		Int int `toml:"_int"`
	}
	type NonStruct int

	date := time.Date(2014, 5, 11, 19, 30, 40, 0, time.UTC)
	dateStr := "2014-05-11T19:30:40Z"

	tests := map[string]struct {
		input      interface{}
		wantOutput string
		wantError  error
	}{
		"bool field": {
			input: struct {
				BoolTrue  bool
				BoolFalse bool
			}{true, false},
			wantOutput: "BoolTrue = true\nBoolFalse = false\n",
		},
		"int fields": {
			input: struct {
				Int   int
				Int8  int8
				Int16 int16
				Int32 int32
				Int64 int64
			}{1, 2, 3, 4, 5},
			wantOutput: "Int = 1\nInt8 = 2\nInt16 = 3\nInt32 = 4\nInt64 = 5\n",
		},
		"uint fields": {
			input: struct {
				Uint   uint
				Uint8  uint8
				Uint16 uint16
				Uint32 uint32
				Uint64 uint64
			}{1, 2, 3, 4, 5},
			wantOutput: "Uint = 1\nUint8 = 2\nUint16 = 3\nUint32 = 4" +
				"\nUint64 = 5\n",
		},
		"float fields": {
			input: struct {
				Float32 float32
				Float64 float64
			}{1.5, 2.5},
			wantOutput: "Float32 = 1.5\nFloat64 = 2.5\n",
		},
		"string field": {
			input:      struct{ String string }{"foo"},
			wantOutput: "String = \"foo\"\n",
		},
		"string field with \\n escape": {
			input:      struct{ String string }{"foo\n"},
			wantOutput: "String = \"foo\\n\"\n",
		},
		"string field and unexported field": {
			input: struct {
				String     string
				unexported int
			}{"foo", 0},
			wantOutput: "String = \"foo\"\n",
		},
		"datetime field in UTC": {
			input:      struct{ Date time.Time }{date},
			wantOutput: fmt.Sprintf("Date = %s\n", dateStr),
		},
		"datetime field as primitive": {
			// Using a map here to fail if isStructOrMap() returns true for
			// time.Time.
			input: map[string]interface{}{
				"Date": date,
				"Int":  1,
			},
			wantOutput: fmt.Sprintf("Date = %s\nInt = 1\n", dateStr),
		},
		"array fields": {
			input: struct {
				IntArray0 [0]int
				IntArray3 [3]int
			}{[0]int{}, [3]int{1, 2, 3}},
			wantOutput: "IntArray0 = []\nIntArray3 = [1, 2, 3]\n",
		},
		"slice fields": {
			input: struct{ IntSliceNil, IntSlice0, IntSlice3 []int }{
				nil, []int{}, []int{1, 2, 3},
			},
			wantOutput: "IntSlice0 = []\nIntSlice3 = [1, 2, 3]\n",
		},
		"datetime slices": {
			input: struct{ DatetimeSlice []time.Time }{
				[]time.Time{date, date},
			},
			wantOutput: fmt.Sprintf("DatetimeSlice = [%s, %s]\n",
				dateStr, dateStr),
		},
		"nested arrays and slices": {
			input: struct {
				SliceOfArrays         [][2]int
				ArrayOfSlices         [2][]int
				SliceOfArraysOfSlices [][2][]int
				ArrayOfSlicesOfArrays [2][][2]int
				SliceOfMixedArrays    [][2]interface{}
				ArrayOfMixedSlices    [2][]interface{}
			}{
				[][2]int{{1, 2}, {3, 4}},
				[2][]int{{1, 2}, {3, 4}},
				[][2][]int{
					{
						{1, 2}, {3, 4},
					},
					{
						{5, 6}, {7, 8},
					},
				},
				[2][][2]int{
					{
						{1, 2}, {3, 4},
					},
					{
						{5, 6}, {7, 8},
					},
				},
				[][2]interface{}{
					{1, 2}, {"a", "b"},
				},
				[2][]interface{}{
					{1, 2}, {"a", "b"},
				},
			},
			wantOutput: `SliceOfArrays = [[1, 2], [3, 4]]
ArrayOfSlices = [[1, 2], [3, 4]]
SliceOfArraysOfSlices = [[[1, 2], [3, 4]], [[5, 6], [7, 8]]]
ArrayOfSlicesOfArrays = [[[1, 2], [3, 4]], [[5, 6], [7, 8]]]
SliceOfMixedArrays = [[1, 2], ["a", "b"]]
ArrayOfMixedSlices = [[1, 2], ["a", "b"]]
`,
		},
		"empty slice": {
			input:      struct{ Empty []interface{} }{[]interface{}{}},
			wantOutput: "Empty = []\n",
		},
		"(error) slice with element type mismatch (string and integer)": {
			input:      struct{ Mixed []interface{} }{[]interface{}{1, "a"}},
			wantOutput: "Mixed = [1, \"a\"]\n",
		},
		"(error) slice with element type mismatch (integer and float)": {
			input:      struct{ Mixed []interface{} }{[]interface{}{1, 2.5}},
			wantOutput: "Mixed = [1, 2.5]\n",
		},
		"slice with elems of differing Go types, same TOML types": {
			input: struct {
				MixedInts   []interface{}
				MixedFloats []interface{}
			}{
				[]interface{}{
					int(1), int8(2), int16(3), int32(4), int64(5),
					uint(1), uint8(2), uint16(3), uint32(4), uint64(5),
				},
				[]interface{}{float32(1.5), float64(2.5)},
			},
			wantOutput: "MixedInts = [1, 2, 3, 4, 5, 1, 2, 3, 4, 5]\n" +
				"MixedFloats = [1.5, 2.5]\n",
		},
		"(error) slice w/ element type mismatch (one is nested array)": {
			input: struct{ Mixed []interface{} }{
				[]interface{}{1, []interface{}{2}},
			},
			wantOutput: "Mixed = [1, [2]]\n",
		},
		"(error) slice with 1 nil element": {
			input:     struct{ NilElement1 []interface{} }{[]interface{}{nil}},
			wantError: errArrayNilElement,
		},
		"(error) slice with 1 nil element (and other non-nil elements)": {
			input: struct{ NilElement []interface{} }{
				[]interface{}{1, nil},
			},
			wantError: errArrayNilElement,
		},
		"simple map": {
			input:      map[string]int{"a": 1, "b": 2},
			wantOutput: "a = 1\nb = 2\n",
		},
		"map with interface{} value type": {
			input:      map[string]interface{}{"a": 1, "b": "c"},
			wantOutput: "a = 1\nb = \"c\"\n",
		},
		"map with interface{} value type, some of which are structs": {
			input: map[string]interface{}{
				"a": struct{ Int int }{2},
				"b": 1,
			},
			wantOutput: "b = 1\n\n[a]\n  Int = 2\n",
		},
		"nested map": {
			input: map[string]map[string]int{
				"a": {"b": 1},
				"c": {"d": 2},
			},
			wantOutput: "[a]\n  b = 1\n\n[c]\n  d = 2\n",
		},
		"nested struct": {
			input: struct{ Struct struct{ Int int } }{
				struct{ Int int }{1},
			},
			wantOutput: "[Struct]\n  Int = 1\n",
		},
		"nested struct and non-struct field": {
			input: struct {
				Struct struct{ Int int }
				Bool   bool
			}{struct{ Int int }{1}, true},
			wantOutput: "Bool = true\n\n[Struct]\n  Int = 1\n",
		},
		"2 nested structs": {
			input: struct{ Struct1, Struct2 struct{ Int int } }{
				struct{ Int int }{1}, struct{ Int int }{2},
			},
			wantOutput: "[Struct1]\n  Int = 1\n\n[Struct2]\n  Int = 2\n",
		},
		"deeply nested structs": {
			input: struct {
				Struct1, Struct2 struct{ Struct3 *struct{ Int int } }
			}{
				struct{ Struct3 *struct{ Int int } }{&struct{ Int int }{1}},
				struct{ Struct3 *struct{ Int int } }{nil},
			},
			wantOutput: "[Struct1]\n  [Struct1.Struct3]\n    Int = 1" +
				"\n\n[Struct2]\n",
		},
		"nested struct with nil struct elem": {
			input: struct {
				Struct struct{ Inner *struct{ Int int } }
			}{
				struct{ Inner *struct{ Int int } }{nil},
			},
			wantOutput: "[Struct]\n",
		},
		"nested struct with no fields": {
			input: struct {
				Struct struct{ Inner struct{} }
			}{
				struct{ Inner struct{} }{struct{}{}},
			},
			wantOutput: "[Struct]\n  [Struct.Inner]\n",
		},
		"struct with tags": {
			input: struct {
				Struct struct {
					Int int `toml:"_int"`
				} `toml:"_struct"`
				Bool bool `toml:"_bool"`
			}{
				struct {
					Int int `toml:"_int"`
				}{1}, true,
			},
			wantOutput: "_bool = true\n\n[_struct]\n  _int = 1\n",
		},
		"embedded struct": {
			input:      struct{ Embedded }{Embedded{1}},
			wantOutput: "_int = 1\n",
		},
		"embedded *struct": {
			input:      struct{ *Embedded }{&Embedded{1}},
			wantOutput: "_int = 1\n",
		},
		"nested embedded struct": {
			input: struct {
				Struct struct{ Embedded } `toml:"_struct"`
			}{struct{ Embedded }{Embedded{1}}},
			wantOutput: "[_struct]\n  _int = 1\n",
		},
		"nested embedded *struct": {
			input: struct {
				Struct struct{ *Embedded } `toml:"_struct"`
			}{struct{ *Embedded }{&Embedded{1}}},
			wantOutput: "[_struct]\n  _int = 1\n",
		},
		"embedded non-struct": {
			input:      struct{ NonStruct }{5},
			wantOutput: "NonStruct = 5\n",
		},
		"array of tables": {
			input: struct {
				Structs []*struct{ Int int } `toml:"struct"`
			}{
				[]*struct{ Int int }{{1}, {3}},
			},
			wantOutput: "[[struct]]\n  Int = 1\n\n[[struct]]\n  Int = 3\n",
		},
		"array of tables order": {
			input: map[string]interface{}{
				"map": map[string]interface{}{
					"zero": 5,
					"arr": []map[string]int{
						{
							"friend": 5,
						},
					},
				},
			},
			wantOutput: "[map]\n  zero = 5\n\n  [[map.arr]]\n    friend = 5\n",
		},
		"empty key name": {
			input:      map[string]int{"": 1},
			wantOutput: `"" = 1` + "\n",
		},
		"key with \\n escape": {
			input:      map[string]string{"\n": "\n"},
			wantOutput: `"\n" = "\n"` + "\n",
		},

		"empty map name": {
			input: map[string]interface{}{
				"": map[string]int{"v": 1},
			},
			wantOutput: "[\"\"]\n  v = 1\n",
		},
		"(error) top-level slice": {
			input:     []struct{ Int int }{{1}, {2}, {3}},
			wantError: errNoKey,
		},
		"(error) map no string key": {
			input:     map[int]string{1: ""},
			wantError: errNonString,
		},

		"tbl-in-arr-struct": {
			input: struct {
				Arr [][]struct{ A, B, C int }
			}{[][]struct{ A, B, C int }{{{1, 2, 3}, {4, 5, 6}}}},
			wantOutput: "Arr = [[{A = 1, B = 2, C = 3}, {A = 4, B = 5, C = 6}]]",
		},

		"tbl-in-arr-map": {
			input: map[string]interface{}{
				"arr": []interface{}{[]interface{}{
					map[string]interface{}{
						"a": []interface{}{"hello", "world"},
						"b": []interface{}{1.12, 4.1},
						"c": 1,
						"d": map[string]interface{}{"e": "E"},
						"f": struct{ A, B int }{1, 2},
						"g": []struct{ A, B int }{{3, 4}, {5, 6}},
					},
				}},
			},
			wantOutput: `arr = [[{a = ["hello", "world"], b = [1.12, 4.1], c = 1, d = {e = "E"}, f = {A = 1, B = 2}, g = [{A = 3, B = 4}, {A = 5, B = 6}]}]]`,
		},

		"slice of slice": {
			input: struct {
				Slices [][]struct{ Int int }
			}{
				[][]struct{ Int int }{{{1}}, {{2}}, {{3}}},
			},
			wantOutput: "Slices = [[{Int = 1}], [{Int = 2}], [{Int = 3}]]",
		},
	}
	for label, test := range tests {
		encodeExpected(t, label, test.input, test.wantOutput, test.wantError)
	}
}
