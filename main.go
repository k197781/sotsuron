package main

import(
	"fmt"
	"os/exec"
	"time"
	"log"
)

func main() {
	for {
		out, err := exec.Command("sh", "-c", "netstat -tan | grep ':80' | wc -l").Output()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(out))
		time.Sleep(1 * time.Second)
	}
}
