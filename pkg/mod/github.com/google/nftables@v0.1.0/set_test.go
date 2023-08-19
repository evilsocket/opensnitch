package nftables

import (
	"reflect"
	"testing"
)

// unknownNFTMagic is an nftMagic value that's unhandled by this
// library. We use two of them below.
const unknownNFTMagic uint32 = 1<<SetConcatTypeBits - 2

func genSetKeyType(types ...uint32) uint32 {
	c := types[0]
	for i := 1; i < len(types); i++ {
		c = c<<SetConcatTypeBits | types[i]
	}
	return c
}

func TestValidateNFTMagic(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		nftMagicPacked uint32
		pass           bool
		invalid        []uint32
	}{
		{
			name:           "Single valid nftMagic",
			nftMagicPacked: genSetKeyType(7),
			pass:           true,
			invalid:        nil,
		},
		{
			name:           "Single unknown nftMagic",
			nftMagicPacked: genSetKeyType(unknownNFTMagic),
			pass:           false,
			invalid:        []uint32{unknownNFTMagic},
		},
		{
			name:           "Multiple valid nftMagic",
			nftMagicPacked: genSetKeyType(7, 13),
			pass:           true,
			invalid:        nil,
		},
		{
			name:           "Multiple nftMagic with 1 unknown",
			nftMagicPacked: genSetKeyType(7, 13, unknownNFTMagic),
			pass:           false,
			invalid:        []uint32{unknownNFTMagic},
		},
		{
			name:           "Multiple nftMagic with 2 unknown",
			nftMagicPacked: genSetKeyType(7, 13, unknownNFTMagic, unknownNFTMagic+1),
			pass:           false,
			invalid:        []uint32{unknownNFTMagic + 1, unknownNFTMagic},
			// Invalid entries will appear in reverse order
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalid, pass := validateKeyType(tt.nftMagicPacked)
			if pass && !tt.pass {
				t.Fatalf("expected to fail but succeeded")
			}
			if !pass && tt.pass {
				t.Fatalf("expected to succeed but failed with invalid nftMagic: %+v", invalid)
			}
			if !reflect.DeepEqual(tt.invalid, invalid) {
				t.Fatalf("Expected invalid: %+v but got: %+v", tt.invalid, invalid)
			}
		})
	}
}

func TestConcatSetType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		types       []SetDatatype
		err         error
		concatName  string
		concatBytes uint32
		concatMagic uint32
	}{
		{
			name:  "Concatenate six (too many) IPv4s",
			types: []SetDatatype{TypeIPAddr, TypeIPAddr, TypeIPAddr, TypeIPAddr, TypeIPAddr, TypeIPAddr},
			err:   ErrTooManyTypes,
		},
		{
			name:        "Concatenate five IPv4s",
			types:       []SetDatatype{TypeIPAddr, TypeIPAddr, TypeIPAddr, TypeIPAddr, TypeIPAddr},
			err:         nil,
			concatName:  "ipv4_addr . ipv4_addr . ipv4_addr . ipv4_addr . ipv4_addr",
			concatBytes: 20,
			concatMagic: 0x071c71c7,
		},
		{
			name:        "Concatenate IPv6 and port",
			types:       []SetDatatype{TypeIP6Addr, TypeInetService},
			err:         nil,
			concatName:  "ipv6_addr . inet_service",
			concatBytes: 20,
			concatMagic: 0x0000020d,
		},
		{
			name:        "Concatenate protocol and port",
			types:       []SetDatatype{TypeInetProto, TypeInetService},
			err:         nil,
			concatName:  "inet_proto . inet_service",
			concatBytes: 8,
			concatMagic: 0x0000030d,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			concat, err := ConcatSetType(tt.types...)
			if tt.err != err {
				t.Errorf("ConcatSetType() returned an incorrect error: expected %v but got %v", tt.err, err)
			}
			if err != nil {
				return
			}
			if tt.concatName != concat.Name {
				t.Errorf("invalid concatinated name: expceted %s but got %s", tt.concatName, concat.Name)
			}
			if tt.concatBytes != concat.Bytes {
				t.Errorf("invalid concatinated number of bytes: expceted %d but got %d", tt.concatBytes, concat.Bytes)
			}
			if tt.concatMagic != concat.nftMagic {
				t.Errorf("invalid concatinated magic: expceted %08x but got %08x", tt.concatMagic, concat.nftMagic)
			}
		})
	}
}

func TestConcatSetTypeElements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		types []SetDatatype
	}{
		{
			name:  "concat ip6 . inet_service",
			types: []SetDatatype{TypeIP6Addr, TypeInetService},
		},
		{
			name:  "concat ip . inet_service . ip6",
			types: []SetDatatype{TypeIPAddr, TypeInetService, TypeIP6Addr},
		},
		{
			name:  "concat inet_proto . inet_service",
			types: []SetDatatype{TypeInetProto, TypeInetService},
		},
		{
			name:  "concat ip . ip . ip . ip",
			types: []SetDatatype{TypeIPAddr, TypeIPAddr, TypeIPAddr, TypeIPAddr},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			concat, err := ConcatSetType(tt.types...)
			if err != nil {
				return
			}
			elements := ConcatSetTypeElements(concat)
			if got, want := len(elements), len(tt.types); got != want {
				t.Errorf("invalid number of elements: expected %d, got %d", got, want)
			}
			for i, v := range tt.types {
				if got, want := elements[i].GetNFTMagic(), v.GetNFTMagic(); got != want {
					t.Errorf("invalid element on position %d: expected %d, got %d", i, got, want)
				}
			}
		})
	}
}
