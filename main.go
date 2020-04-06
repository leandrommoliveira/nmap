package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/Ullaakut/nmap"
)

func main() {
	targetIP := "192.168.1.1/24"

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)

	defer cancel()
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targetIP),
		nmap.WithPorts("80, 443, 8080"),
		nmap.WithContext(ctx),
	)

	if err != nil {
		log.Fatal("error : ", err)
	}

	results, warnings, err := scanner.Run()

	if err != nil {
		log.Fatal("error : ", err)
	}

	if warnings != nil {
		log.Fatal("warning : ", warnings)
	}

	for _, hosts := range results.Hosts {
		if len(hosts.Ports) == 0 || len(hosts.Addresses) == 0 {
			continue
		}

		fmt.Printf("IP: %q", hosts.Addresses[0])
		if len(hosts.Addresses) > 1 {
			fmt.Printf(" MAC: %v", hosts.Addresses[1])
		}

		fmt.Printf(" Ports: ")
		for _, port := range hosts.Ports {
			fmt.Printf(" | %s %s %s %s |", strconv.Itoa(int(port.ID)), port.Protocol, port.State, port.Service.Name)
		}

		fmt.Printf("\n")

	}

}
