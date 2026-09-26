package portscan

import (
	"runtime"
	"testing"
)

// TestEngineFootprintDoesNotScaleWithMaxSources pins that an engine which has
// seen no packet costs the same whatever MaxSources is set to.
//
// The source table carves its entries in chunks of tableChunk, and the comment
// on that says why: tableEntry contains pointers, so preallocating the whole
// table "costs the garbage collector real time on a machine that is not being
// scanned", and "an idle desktop pays for the sources it has actually seen".
// The shard's address map must follow the same rule: created with
// make(..., capacity), it would be a map of pointers sized to the full
// capacity, which is exactly the object the collector has to walk and exactly
// the cost the chunking removes.
//
// Measured with the map presized that way: 430 KB at the defaults and 84 MB
// at the maximum MaxSources, with the map accounting for effectively all of
// it, against a slab that costs nothing until the first probe. That would
// also make MaxSources expensive to raise in advance -- and raising it is the
// one remedy the daemon suggests when it reports eviction pressure.
func TestEngineFootprintDoesNotScaleWithMaxSources(t *testing.T) {
	measure := func(maxSources int) uint64 {
		cfg := testConfig()
		cfg.MaxSources = maxSources

		const n = 8
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		engines := make([]*Engine, n)
		for i := range engines {
			engines[i] = newTestEngine(t, cfg, newFakeHost())
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(engines)
		if after.HeapAlloc < before.HeapAlloc {
			return 0
		}
		return (after.HeapAlloc - before.HeapAlloc) / n
	}

	small := measure(DefaultMaxSources)
	large := measure(65536)
	t.Logf("fresh engine: %d bytes at MaxSources=%d, %d bytes at MaxSources=65536",
		small, DefaultMaxSources, large)

	// Sixteen times the capacity must not cost anything like sixteen times the
	// memory. A generous factor of two leaves room for allocator noise while
	// still failing loudly if the map is preallocated: that would show a
	// factor of about 195.
	if small > 0 && large > 2*small {
		t.Fatalf("a fresh engine costs %d bytes at MaxSources=65536 against %d at %d:"+
			" the table is being preallocated rather than grown on demand",
			large, small, DefaultMaxSources)
	}
}
