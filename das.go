/*
 * DAS - DisASsembler (not for MB)
 *
 * Copyright (C) 2017-2018  Namhyung Kim <namhyung@gmail.com>
 *
 * Released under MIT license.
 */
package main

import (
	"bytes"
	"debug/elf"
	"flag"
	gcs "github.com/bnagy/gapstone"
	"log"
	"os"
)

const (
	OPTYPE_OTHER = iota
	OPTYPE_BRANCH
	OPTYPE_RETURN
)

type DasLine struct {
	rawline  string
	offset   int64
	optype   int
	opcode   string // []uint8
	mnemonic string
	args     string
	local    bool  // only for OPTYPE_BRANCH
	target   int64 // only for OPTYPE_BRANCH
	comment  string
}

type DasFunc struct {
	name  string
	start int64
	sect  bool
	fold  bool // for section
	insn  []*DasLine
}

type DasParser struct {
	name   string
	file   *os.File
	elf    *elf.File
	engine *gcs.Engine
	ops    DasArchOps
}

type DasArchOps interface {
	parsePLT()
	parseInsn(gcs.Instruction, elf.Symbol) *DasLine
}

var (
	funcs      []*DasFunc
	csect      *DasFunc         // current section
	strs       map[int64]string // string table
	lastOffset int64            // last code offset
	capstone   bool
)

func init() {
	flag.BoolVar(&capstone, "c", false, "Use capstone disassembler")
}

func initDasParser(target string) *DasParser {
	f, err := os.Open(target)
	if err != nil {
		log.Fatal(err)
	}

	e, err := elf.NewFile(f)
	if err != nil {
		log.Fatal(err)
	}

	return &DasParser{name: target, file: f, elf: e}
}

func finishDasParser(p *DasParser) {
	p.engine.Close()
	p.elf.Close()
	p.file.Close()
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("Usage: das <binary>")
	}

	target := args[0]
	p := initDasParser(target)

	if capstone {
		prepareCapstone(p)
		if p.ops == nil {
			log.Fatal("Architecture not supported (yet)!")
		}

		parseCapstone(p)
	} else {
		var buf *bytes.Buffer

		buf = runCommand("strings", "-t", "x", target)
		parseStrings(buf)

		buf = runCommand("objdump", "-d", "-C", target)
		parseObjdump(buf)
	}

	ShowTUI(p)

	finishDasParser(p)
}
