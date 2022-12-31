//go:build !capstone
// +build !capstone

package main

import (
	"log"
)

func prepareCapstone(p *DasParser) {
	log.Fatal("Capstone is not available")
}

func parseCapstone(p *DasParser) {
}

func parseCapstoneFunc(p *DasParser, fn *DasFunc) {
}
