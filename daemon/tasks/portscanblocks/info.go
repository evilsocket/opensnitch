package portscanblocks

// Info is the reply to PORTSCAN_BLOCK_INFO: one block, why it was made and how
// the firewall applies it -- or one detection the daemon did not block. It is
// fetched on demand rather than sent with every snapshot, which would multiply
// the size of each tick by the size of a scan for rows nobody opened.
type Info struct {
	Blocked
	// Scan is the detection that led to the block. Absent when the daemon
	// does not have it: a block confirmed for a source the engine still knew
	// and the detection history no longer did.
	Scan *Scan `json:"scan,omitempty"`
	// Firewall is the part of the nftables table that drops the address, in
	// the syntax of `nft list table`, read from the kernel when the request
	// was answered.
	Firewall string `json:"firewall,omitempty"`
	// FirewallError says why Firewall is empty: the firewall could not be read,
	// or no longer holds the address. The block is still reported: the user is
	// looking because something seems wrong.
	FirewallError string `json:"firewall_error,omitempty"`
	// Detection is set, instead of the block's fields, for a source the
	// daemon reported and does not block: the details of a row of the
	// history.
	Detection *Detected `json:"detection,omitempty"`
}

// Scan describes a detection. The field names and meanings are those of the
// PortScan message in proto/ui.proto, so that the user interface presents
// both with the same code.
type Scan struct {
	Method            string   `json:"method"`
	MethodDetail      string   `json:"method_detail"`
	SrcMAC            string   `json:"src_mac,omitempty"`
	SrcMACIsSourceOwn bool     `json:"src_mac_is_source_own,omitempty"`
	FlagsSummary      string   `json:"flags_summary,omitempty"`
	DistinctPorts     uint32   `json:"distinct_ports"`
	MinPort           uint32   `json:"min_port"`
	MaxPort           uint32   `json:"max_port"`
	SamplePorts       []uint32 `json:"sample_ports"`
	Protocols         uint32   `json:"protocols"`
	IsProtocolScan    bool     `json:"is_protocol_scan,omitempty"`
	Score             uint32   `json:"score"`
	Interface         string   `json:"interface,omitempty"`
	Targets           []string `json:"targets"`
	FirstSeenUnixnano int64    `json:"first_seen_unixnano,omitempty"`
	LastSeenUnixnano  int64    `json:"last_seen_unixnano,omitempty"`
	Anomalies         []string `json:"anomalies"`
	HasTCPEvidence    bool     `json:"has_tcp_evidence"`
}
