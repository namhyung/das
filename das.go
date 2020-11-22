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
	"fmt"
	"log"
	"os"
	str "strings"
)

const (
	OPTYPE_OTHER = iota
	OPTYPE_BRANCH
	OPTYPE_RETURN
	OPTYPE_INFO
)

type DasLine struct {
	rawline  string
	offset   uint64
	optype   int
	opcode   string // []uint8
	mnemonic string
	args     string
	local    bool   // for OPTYPE_BRANCH
	target   uint64 // for OPTYPE_BRANCH
	indent   int    // for OPTYPE_INFO
	comment  string
}

type DasFunc struct {
	name  string
	sym   elf.Symbol
	start uint64
	sect  bool
	fold  bool // for section
	insn  []*DasLine
}

type DasParser struct {
	name   string
	file   *os.File
	elf    *elf.File
	ops    DasArchOps
	engine interface{}
}

type DasArchOps interface {
	parsePLT()
	parseInsn(interface{}, *elf.Symbol) *DasLine
	describe(insn *DasLine) string
}

var (
	funcs      []*DasFunc
	csect      *DasFunc          // current section
	strs       map[uint64]string // string table
	lastOffset uint64            // last code offset
	capstone   bool
	objdump    string
)

func init() {
	flag.BoolVar(&capstone, "c", false, "Use capstone disassembler")
	flag.StringVar(&objdump, "d", "objdump", "Path to objdump tool")
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
	p.elf.Close()
	p.file.Close()
}

func describeInsn(p *DasParser, insn *DasLine) string {
	if p.ops != nil {
		return fmt.Sprintf("%s: %s (%s)", "instruction",
			str.ToUpper(insn.mnemonic), p.ops.describe(insn))
	}
	return "instruction: " + str.ToUpper(insn.mnemonic)
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

		setupArchOps(p)

		buf = runCommand("strings", "-t", "x", target)
		parseStrings(buf)

		buf = tryCommand(objdump, "-dCl", "--inlines", target)
		if buf.Len() == 0 {
			buf = runCommand(objdump, "-dC", target)
		}
		parseObjdump(p, buf)
	}

	ShowTUI(p)

	finishDasParser(p)
}
