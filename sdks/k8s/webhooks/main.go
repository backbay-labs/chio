package main

import "log"

func main() {
	if err := RunServer(); err != nil {
		log.Fatalf("chio admission webhook: %v", err)
	}
}
