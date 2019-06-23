package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"log"
	"os/exec"
	scv "strconv"
	str "strings"
)

func parseFunction(p *DasParser, b *bytes.Buffer, name, offset string) *DasFunc {
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

		if len(insn_arr) > 2 {
			sym := elf.Symbol{Name: df.name, Value: uint64(df.start)}
			dl := p.ops.parseInsn(insn_arr[2], &sym)
			dl.offset, err = scv.ParseInt(line_arr[0], 16, 64)
			dl.opcode = insn_arr[1]

			df.insn = append(df.insn, dl)

			if lastOffset < dl.offset {
				lastOffset = dl.offset
			}
		} else {
			// leftover from the previous insn, append to it
			last_dl := df.insn[len(df.insn)-1]
			last_dl.opcode += insn_arr[1]
		}
	}

	return df
}

func parseObjdump(p *DasParser, b *bytes.Buffer) {
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
			func_line := str.SplitN(line, " ", 2)
			fn := parseFunction(p, b, func_line[1], func_line[0])
			if fn != nil {
				csect.start++ // abuse it as function count
				funcs = append(funcs, fn)
			}
		default:
		}
	}
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

func runCommand(name string, args ...string) *bytes.Buffer {
	outbuf := new(bytes.Buffer)

	cmd := exec.Command(name, args...)
	cmd.Stdout = outbuf

	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	return outbuf
}

func setupArchOps(p *DasParser) {
	switch p.elf.Machine {
	case elf.EM_X86_64:
		p.ops = getArchOpsX86(p)
	case elf.EM_386:
		p.ops = getArchOpsX86(p)
	case elf.EM_ARM:
		// FIXME
		p.ops = getArchOpsAArch64(p)
	case elf.EM_AARCH64:
		p.ops = getArchOpsAArch64(p)
	default:
		log.Fatal("Unsupported Architect\n")
	}

}
