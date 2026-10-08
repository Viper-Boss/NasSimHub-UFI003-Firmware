package main

import (
	"github.com/human-agent65535/nassimhub-node/agent/internal/systemadmin"
	"log"
)

func main() {
	if err := systemadmin.Serve(); err != nil {
		log.Fatal(err)
	}
}
