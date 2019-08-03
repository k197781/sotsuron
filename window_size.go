package main

import (
	"fmt"
	"log"
	"time"
	"os/exec"
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
	connectionStartTimes := make(map[string]time.Time)
	var minWindowSize int64 = 10000
	var maxConnectiontime float64 = 5.0

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

		// SYNフラグが立っている時
		// ・window scaleを変数windowScalesに格納
		// ・コネクションの開始時間を格納
		if tcp.SYN == true {
			for _, opt := range opts {
				if opt.OptionType.String() == "WindowScale" {
					windowScales[src] = opt.OptionData
					fmt.Printf("window scale: %d\n", opt.OptionData)
				}
			}
			connectionStartTimes[src] = time.Now()
		// SYNフラグが立っていない時
		// ・window sizeを計算
		// ・接続時間を計算
		} else {
			CalculatedWindowSize := calculateWindowSize(tcp.Window, windowScales[src])
			fmt.Printf("window size: %d calculated window size: %d\n", tcp.Window, CalculatedWindowSize)
			connectionTime := time.Since(connectionStartTimes[src])
			fmt.Printf("connection time: %f \n", connectionTime.Seconds())
			if CalculatedWindowSize < minWindowSize {
				closeConnection(ip.SrcIP.String())
			}
			if connectionTime.Seconds() > maxConnectiontime {
				closeConnection(ip.SrcIP.String())
			}
		}
	}
}

func calculateWindowSize(windowSize uint16, windowScale []byte) int64 {
	padding := make([]byte, 8-len(windowScale))
	windowScaleUnit64 := binary.BigEndian.Uint64(append(padding, windowScale...))
	return int64(windowSize) << windowScaleUnit64
}

func closeConnection(ip string) {
	err := exec.Command("ufw", "insert", "1", "deny", "from", ip).Run()
	if err != nil {

		log.Printf("can not close connection from " + ip)
	}
	log.Printf("close connection from " + ip)
}
