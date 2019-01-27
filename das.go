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
	"flag"
	"log"
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

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("Usage: das <binary>")
	}

	target := args[0]

	if capstone {
		f, e, engine := prepareCapstone(target)
		defer engine.Close()
		defer e.Close()
		defer f.Close()

		parseCapstone(e, engine)
	} else {
		var buf *bytes.Buffer

		buf = runCommand("strings", "-t", "x", target)
		parseStrings(buf)

		buf = runCommand("objdump", "-d", "-C", target)
		parseObjdump(buf)
	}

	ShowTUI(target)
}
