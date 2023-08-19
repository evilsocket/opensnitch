// +build !linux

package elf

// not supported; dummy struct
type BPFKProbePerf struct{}
type SectionParams struct{}
type Map struct{}

func (b *Module) Load(parameters map[string]SectionParams) error {
	return errNotSupported
}

func NewBpfPerfEvent(fileName string) *BPFKProbePerf {
	// not supported
	return nil
}

func (b *BPFKProbePerf) Load() error {
	return errNotSupported
}

func (b *BPFKProbePerf) PollStart(mapName string, receiverChan chan []byte, lostChan chan uint64) {
	// not supported
	return
}

func (b *BPFKProbePerf) PollStop(mapName string) {
	// not supported
	return
}

func (m *Map) Fd() int {
        // not supported
	return -1
}
