package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func main() {
	maxConnection := 1000
	for {
		out, err := exec.Command("sh", "-c", "netstat -tan | grep '3000' | wc -l").Output()
		if err != nil {
			log.Fatal(err)
		}
		connectionStr := strings.Replace(string(out), " ", "", -1)
		connectionStr = strings.Replace(connectionStr, "\n", "", -1)
		connection, _ := strconv.Atoi(connectionStr)
		fmt.Println(connection)
		if connection > maxConnection {
			os.Setenv("ISATTACKED", "false")
			fmt.Println(os.Getenv("ISATTACKED"))
		}
		time.Sleep(1 * time.Second)
	}
}
