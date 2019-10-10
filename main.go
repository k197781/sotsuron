package main

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var IsAttacked bool = false

func main() {
	maxConnection := 1000
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
		fmt.Println(connection)
		if connection > maxConnection {
			IsAttacked = true
		}
		time.Sleep(1 * time.Second)
	}
}
