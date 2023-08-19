package pkg

func fn() {
	var m map[string]int
	var b []byte
	_ = m[string(b)]
	_ = m[string(b)]
	s1 := string(b) // want `m\[string\(key\)\] would be more efficient than k := string\(key\); m\[k\]`
	_ = m[s1]
	_ = m[s1]

	s2 := string(b)
	_ = m[s2]
	_ = m[s2]
	println(s2)
}
