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
	"fmt"
	"log"
	"os"
	"os/exec"
	scv "strconv"
	str "strings"
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
)

func parseInsn(df *DasFunc, dl *DasLine, raw_line string) {
	dl.rawline = raw_line

	tmp := str.SplitN(raw_line, " ", 2)
	dl.mnemonic = tmp[0]

	if str.HasPrefix(dl.mnemonic, "ret") {
		dl.optype = OPTYPE_RETURN
	}

	if len(tmp) == 1 {
		return
	}

	dl.args = str.TrimSpace(tmp[1])

	if str.Index(dl.args, "#") != -1 {
		tmp = str.Split(dl.args, "#")
		dl.args = str.TrimSpace(tmp[0])
		dl.comment = str.TrimSpace(tmp[1])
	}

	if str.HasPrefix(dl.mnemonic, "j") ||
		str.HasPrefix(dl.mnemonic, "call") {
		dl.optype = OPTYPE_BRANCH

		tmp = str.Split(dl.args, " ")
		if len(tmp) == 2 {
			dl.target, _ = scv.ParseInt(tmp[0], 16, 64)
			dl.args = tmp[1]

			// if it's a jump in a same function, just save the offset
			if str.HasPrefix(dl.args, df.name[0:len(df.name)-1]) &&
				(dl.args[len(df.name)-1] == '+' ||
					dl.args[len(df.name)-1] == '>') {
				dl.args = fmt.Sprintf("%#x", dl.target-df.start)
				dl.local = true
			}
		}
	}
}

func parseFunction(b *bytes.Buffer, name, offset string) *DasFunc {
	var err error
	df := new(DasFunc)
	df.name = str.TrimSuffix(name, ":\n")
	df.start, err = scv.ParseInt(offset, 16, 64)
	if err != nil {
		log.Println(err)
		return nil
	}

	for {
		line, err := b.ReadString('\n')
		line = str.TrimSpace(line)
		if len(line) == 0 {
			break
		}
		if err != nil {
			log.Println(err)
		}

		if line == "..." {
			continue
		}

		//          [TAB]                   [TAB]
		//   4aeba0:	64 48 8b 0c 25 f8 ff 	mov    %fs:0xfffffffffffffff8,%rcx
		//   4aeba7:	ff ff
		//   4aeba9:	48 8d 44 24 c8       	lea    -0x38(%rsp),%rax
		//   4aeefe:	48 3b 41 10          	cmp    0x10(%rcx),%rax
		//   4aef02:	0f 86 f6 01 00 00    	jbe    4af0fe <main.main+0x20e>

		line_arr := str.SplitN(line, ":", 2)
		insn_arr := str.Split(line_arr[1], "\t")

		dl := new(DasLine)
		dl.offset, err = scv.ParseInt(line_arr[0], 16, 64)
		dl.opcode = insn_arr[1]

		if len(insn_arr) > 2 {
			parseInsn(df, dl, insn_arr[2])

			df.insn = append(df.insn, dl)
		} else {
			// leftover from the previous insn, append to it
			last_dl := df.insn[len(df.insn)-1]
			last_dl.opcode += dl.opcode
		}

		if lastOffset < dl.offset {
			lastOffset = dl.offset
		}
	}

	return df
}

func parseDisas(b *bytes.Buffer) {
	//var filename, format string
	var line string
	var err error

	for {
		line, err = b.ReadString('\n')
		if err != nil {
			break
		}

		switch {
		case str.Contains(line, "file format "):
			// das:     file format elf64-x86-64
			//file_name := str.Split(line, ":")[0]
			//file_format := str.Split(line, "file format ")[1]
		case str.HasPrefix(line, "Disassembly of section"):
			// Disassembly of section .text:
			sect := new(DasFunc)
			sect.name = str.Split(line, "section ")[1]
			sect.name = str.TrimRight(sect.name, ":\n")
			sect.sect = true
			funcs = append(funcs, sect)
			csect = sect
		case str.HasSuffix(line, ">:\n"):
			// 00000000004aeba0 <main.main>:
			func_line := str.Split(line, " ")
			fn := parseFunction(b, func_line[1], func_line[0])
			if fn != nil {
				csect.start++ // abuse it as function count
				funcs = append(funcs, fn)
			}
		default:
		}
	}
}

func LookupInsn(name string) string {
	desc := Insn_x86_64[name]
	if len(desc) > 0 {
		return desc
	}

	// check suffix for conditional instructions
	for _, insn := range CondInsn_x86_64 {
		cond := ""

		if !str.HasPrefix(name, insn) {
			continue
		}

		for cc, cdesc := range Cond_x86_64 {
			if name[len(insn):len(name)] == cc {
				cond = cdesc
			}
		}

		if len(cond) > 0 {
			return fmt.Sprintf("%s If %s", Insn_x86_64[insn], cond)
		}
	}

	// if it has a size suffix (bwlq), try to match again without it
	if str.HasSuffix(name, "b") || str.HasSuffix(name, "w") ||
		str.HasSuffix(name, "l") || str.HasSuffix(name, "q") {
		return Insn_x86_64[name[0:len(name)-1]]
	}

	return ""
}

func parseStrings(b *bytes.Buffer) {
	var line string
	var err error
	var ofs int64

	strs = make(map[int64]string)

	for {
		line, err = b.ReadString('\n')
		if err != nil {
			break
		}

		data := str.SplitN(str.TrimSpace(line), " ", 2)
		if len(data) == 1 {
			continue
		}

		ofs, err = scv.ParseInt(data[0], 16, 64)
		strs[ofs] = data[1]
	}
}

func lookupStrings(comment string, ignoreCode bool) string {
	cmt := str.Split(comment, " ")
	offset, err := scv.ParseInt(cmt[0], 16, 64)

	if err != nil {
		return fmt.Sprintf("%s: %s", comment, err.Error)
	}

	// some code might be guessed as strings, ignore it
	if ignoreCode && offset <= lastOffset {
		return comment
	}

	strconst, ok := strs[offset]
	if ok {
		return fmt.Sprintf("%x \"%s\"", offset, strconst)
	}
	return comment
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: das <binary>")
		os.Exit(1)
	}

	target := args[0]
	var out bytes.Buffer

	strings := exec.Command("strings", "-t", "x", target)
	strings.Stdout = &out

	err := strings.Run()
	if err != nil {
		log.Fatal(err)
	}

	parseStrings(&out)
	out.Reset()

	objdump := exec.Command("objdump", "-d", target)
	objdump.Stdout = &out

	err = objdump.Run()
	if err != nil {
		log.Fatal(err)
	}

	parseDisas(&out)

	ShowTUI(target)
}
