// +build !linux

package elf

type PerfMap struct{}

func InitPerfMap(b *Module, mapName string, receiverChan chan []byte, lostChan chan uint64) (*PerfMap, error) {
	return nil, errNotSupported
}

func (pm *PerfMap) SetTimestampFunc(timestamp func(*[]byte) uint64) {}

func (pm *PerfMap) PollStart() {}

func (pm *PerfMap) PollStop() {}

func NowNanoseconds() uint64 {
	return 0
}
