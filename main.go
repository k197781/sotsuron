package main

import (
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var IsAttacked bool = false
var timeDisconnectionRate time.Duration = 1
var attackedTime time.Duration = 1
var disconnectionCount int64 = 1

func main() {
	maxConnection := 800
	go func() {
		packetMonitoring()
	}()

	for {
		out, err := exec.Command("sh", "-c", "netstat -tan | grep ':80' | wc -l").Output()
		if err != nil {
			log.Fatal(err)
		}
		connectionStr := strings.Replace(string(out), " ", "", -1)
		connectionStr = strings.Replace(connectionStr, "\n", "", -1)
		connection, _ := strconv.Atoi(connectionStr)
		log.Println(connection)
		if connection > maxConnection {
			if IsAttacked == false {
				IsAttacked = true
				log.Printf("this server is Attacked !!!")
			}
			if attackedTime % 5 == 0{
				disconnectionCount++
				log.Printf("disconnectionCount is up to " + strconv.FormatInt(disconnectionCount,10))
			}
			attackedTime++
		} else {
			IsAttacked = false
		}
		time.Sleep(timeDisconnectionRate * time.Second)
	}
}
