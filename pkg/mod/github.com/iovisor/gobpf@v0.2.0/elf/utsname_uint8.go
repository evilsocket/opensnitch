// +build linux,arm linux,ppc64 linux,ppc64le s390x

package elf

func utsnameStr(in []uint8) string {
	out := make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			break
		}
		out = append(out, byte(in[i]))
	}
	return string(out)
}
