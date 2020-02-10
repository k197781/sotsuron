package main

import (
	"log"
	"time"
	"strconv"
	"strings"
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
	closedIpList []string
	hostIp       string = "10.1.200.100"
	hostPort     string = "80"
)

func packetMonitoring() {
	windowScales := make(map[string][]byte)
	connectionStartTimes := make(map[string]time.Time)
	// var minWindowSize int64 = 200
	var maxConnectiontime float64 = 10.0
	var windowsizeDisconnectionRate int64 = 64
	closedIpList = make([]string, 100)

	handle, err = pcap.OpenLive(device, int32(0xFFFF), true, pcap.BlockForever,)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	var filter string = "tcp and port " + hostPort + " and dst host " + hostIp
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
		src := ip.SrcIP.String() + tcp.SrcPort.String()
		opts := tcp.Options

		// SYNフラグが立っている時
		// ・window scaleを変数windowScalesに格納
		// ・コネクションの開始時間を格納
		if tcp.SYN == true {
			for _, opt := range opts {
				if opt.OptionType.String() == "WindowScale" {
					windowScales[src] = opt.OptionData
				}
			}
			connectionStartTimes[src] = time.Now()
		// SYNフラグが立っていない時
		// ・window sizeを計算
		// ・接続時間を計算
		} else {
			if isHttpRequest(packet) == false {
				continue
			}
			CalculatedWindowSize := calculateWindowSize(tcp.Window, windowScales[src])
			connectionTime := time.Since(connectionStartTimes[src])
			// windowsizeの型を調整する
			if CalculatedWindowSize <= windowsizeDisconnectionRate*disconnectionCount+256 && IsAttacked {
				closeConnection(ip.SrcIP.String(), "Window size is " + strconv.FormatInt(CalculatedWindowSize, 10))
				closeSocket(ip.SrcIP.String())
			}
			if connectionTime.Seconds() > maxConnectiontime && IsAttacked {
				closeConnection(ip.SrcIP.String(), "Connection time is to long")
				closeSocket(ip.SrcIP.String())
			}
		}
	}
}

func calculateWindowSize(windowSize uint16, windowScale []byte) int64 {
	padding := make([]byte, 8-len(windowScale))
	windowScaleUnit64 := binary.BigEndian.Uint64(append(padding, windowScale...))
	return int64(windowSize) << windowScaleUnit64
}

func closeConnection(ip string, result string) {
	for _, closedIp := range closedIpList {
		if closedIp == ip {
			return
		}
	}

	err := exec.Command("ufw", "insert", "1", "deny", "from", ip).Run()
	if err != nil {
		log.Printf("can not close connection from " + ip + ", because of " + result)
	}

	closedIpList = append(closedIpList, ip)
	log.Printf("Close connection from " + ip + ". " + result)
}

func isHttpRequest(packet gopacket.Packet) bool {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer == nil {
		return false
	}
	return true
}

func closeSocket(ip string) bool {
	out, err := exec.Command("sh", "-c", "netstat -tan | grep ':80' | grep '" + ip + "'").Output()
	if err != nil {
		log.Printf("No reset connection from " + ip)
		return false
	}
	connectionStr := string(out)
	connectionStrList := strings.Split(connectionStr, "\n")

	// close socket for each of connection from attacked server
	for _, str := range connectionStrList {
		strList := strings.Split(str, " ")
		for _, s := range strList {
			if strings.HasPrefix(s, ip) {
				port := strings.TrimLeft(s, ip + ":")
				err :=  exec.Command("sh", "-c", "ss -K dst " + ip + " dport = " + port).Run()
				if err != nil {
					log.Printf("Can not reset connection from " + ip)
				}
				continue	
			}
		}
	}
	return true
}
