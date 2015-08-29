package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	//"github.com/google/gopacket/bsdbpf"
	"github.com/hb9cwp/gopacket/bsdbpf"
)

func main() {
	var err error
	var ci gopacket.CaptureInfo
	var frame []byte
	sniffer, err := bsdbpf.NewBPFSniffer("alc0", nil)
	if err != nil {
		panic(err)
	}

	for {
		frame,ci,err = sniffer.ReadPacketData()
	        if err != nil {
	         panic(err)
	        }
		fmt.Printf("%s ", ci.Timestamp)
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

		// Iterate over all layers, printing out each layer type
		for _, layer := range packet.Layers() {
			fmt.Printf(" %v - ", layer.LayerType())
		}

		// Get the TCP layer from this packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("src:%d to dst:%d\n", tcp.SrcPort, tcp.DstPort)
		}
		fmt.Println()
	}
}
