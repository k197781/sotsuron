package main

import (
	"fmt"
	"log"
	"time"
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)

var (
	device       string = "ens160"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

func main() {
	windowScales := make(map[string][]byte)
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter string = "tcp and not src host 10.1.200.100"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
                if ipLayer == nil {
			log.Print("ip header is nil")
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)
		if tcpLayer == nil {
			log.Print("tcp header is nil")
			continue
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		src := ip.SrcIP.String() +  tcp.SrcPort.String()
		opts := tcp.Options
		// SYNフラグが立っている時は，window scaleを変数windowScalesに格納
		if tcp.SYN == true {
			for _, opt := range opts {
				if opt.OptionType.String() == "WindowScale" {
					windowScales[src] = opt.OptionData
					fmt.Printf("window scale: %d\n", opt.OptionData)
				}
			}
		} else {
			CalculatedWindowSize := calculateWindowSize(tcp.Window, windowScales[src])
			fmt.Printf("window size: %d calculated window size: %d\n", tcp.Window, CalculatedWindowSize)
		}
	}
}

func calculateWindowSize(windowSize uint16, windowScale []byte) int64 {
	padding := make([]byte, 8-len(windowScale))
	windowScaleUnit64 := binary.BigEndian.Uint64(append(padding, windowScale...))
	return int64(windowSize) << windowScaleUnit64
}

