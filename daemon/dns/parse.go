package dns

import (
	"github.com/gustavo-iniguez-goya/opensnitch/daemon/netfilter"
	"github.com/google/gopacket/layers"
)

func GetQuestions(nfp *netfilter.Packet) (questions []string) {
	dnsLayer := nfp.Packet.Layer(layers.LayerTypeDNS)
    if dnsLayer == nil {
        return questions
    }

	dns, _ := dnsLayer.(*layers.DNS)
    for _, dnsQuestion := range dns.Questions {
		questions = append(questions, string(dnsQuestion.Name))
	}

	return questions
}
