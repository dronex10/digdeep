package main

import (
	"fmt"
	"os"

	"github.com/dronex10/digdeep/cmd"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
