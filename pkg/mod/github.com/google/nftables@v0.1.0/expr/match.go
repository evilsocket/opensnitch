package expr

import (
	"bytes"
	"encoding/binary"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/xt"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// See https://git.netfilter.org/libnftnl/tree/src/expr/match.c?id=09456c720e9c00eecc08e41ac6b7c291b3821ee5#n30
type Match struct {
	Name string
	Rev  uint32
	Info xt.InfoAny
}

func (e *Match) marshal(fam byte) ([]byte, error) {
	// Per https://git.netfilter.org/libnftnl/tree/src/expr/match.c?id=09456c720e9c00eecc08e41ac6b7c291b3821ee5#n38
	name := e.Name
	// limit the extension name as (some) user-space tools do and leave room for
	// trailing \x00
	if len(name) >= /* sic! */ XTablesExtensionNameMaxLen {
		name = name[:XTablesExtensionNameMaxLen-1] // leave room for trailing \x00.
	}
	// Marshalling assumes that the correct Info type for the particular table
	// family and Match revision has been set.
	info, err := xt.Marshal(xt.TableFamily(fam), e.Rev, e.Info)
	if err != nil {
		return nil, err
	}
	attrs := []netlink.Attribute{
		{Type: unix.NFTA_MATCH_NAME, Data: []byte(name + "\x00")},
		{Type: unix.NFTA_MATCH_REV, Data: binaryutil.BigEndian.PutUint32(e.Rev)},
		{Type: unix.NFTA_MATCH_INFO, Data: info},
	}
	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}

	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("match\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

func (e *Match) unmarshal(fam byte, data []byte) error {
	// Per https://git.netfilter.org/libnftnl/tree/src/expr/match.c?id=09456c720e9c00eecc08e41ac6b7c291b3821ee5#n65
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return err
	}

	var info []byte
	ad.ByteOrder = binary.BigEndian
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_MATCH_NAME:
			// We are forgiving here, accepting any length and even missing terminating \x00.
			e.Name = string(bytes.TrimRight(ad.Bytes(), "\x00"))
		case unix.NFTA_MATCH_REV:
			e.Rev = ad.Uint32()
		case unix.NFTA_MATCH_INFO:
			info = ad.Bytes()
		}
	}
	if err = ad.Err(); err != nil {
		return err
	}
	e.Info, err = xt.Unmarshal(e.Name, xt.TableFamily(fam), e.Rev, info)
	return err
}
