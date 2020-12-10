package main

import (
	"bufio"
	"debug/elf"
	"fmt"
	"io"
	"log"
	"os/exec"
	scv "strconv"
	str "strings"
)

const (
	hugeOutput int = 300000
)

var (
	parsedLines int
)

func parseFunction(p *DasParser, br *bufio.Reader, name, offset string) *DasFunc {
	var err error
	var currFunc string

	df := new(DasFunc)
	df.name = str.TrimSuffix(name, ":\n")
	df.start, err = scv.ParseUint(offset, 16, 64)
	if err != nil {
		log.Println(err)
		return nil
	}

	for {
		line, err := br.ReadString('\n')
		parsedLines += 1

		// info lines
		if len(line) > 1 && !str.Contains(line, ":\t") {
			line = str.TrimSpace(line)

			if str.HasSuffix(line, "):") {
				idx := str.LastIndex(line, "(")
				if idx != -1 {
					currFunc = line[0:idx]
				} else {
					currFunc = line
				}
			} else if str.HasPrefix(line, "inlined by") {
				if currFunc != "" && len(df.insn) > 0 {
					dl := df.insn[len(df.insn)-1]
					if dl.optype == OPTYPE_INFO {
						if !str.HasPrefix(dl.args, "inlined by") {
							dl.args = line
						}
						dl.indent++
					}
				}
			} else if currFunc != "" {
				// source filename and line info
				dl := &DasLine{
					optype:   OPTYPE_INFO,
					mnemonic: currFunc,
					args:     line,
					rawline:  currFunc + "(): " + line,
				}
				df.insn = append(df.insn, dl)
			}
			continue
		}
		// we will process info lines only if it comes right after
		// the function name
		currFunc = ""

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
		//main():
		//file/path/name.c:12
		//   4aeba0:	64 48 8b 0c 25 f8 ff 	mov    %fs:0xfffffffffffffff8,%rcx
		//   4aeba7:	ff ff
		//   4aeba9:	48 8d 44 24 c8       	lea    -0x38(%rsp),%rax
		//   4aeefe:	48 3b 41 10          	cmp    0x10(%rcx),%rax
		//   4aef02:	0f 86 f6 01 00 00    	jbe    4af0fe <main.main+0x20e>
		//other_func():
		//file/path/name.c:64
		//inlined by file/path/name.c:15

		line_arr := str.SplitN(line, ":", 2)
		insn_arr := str.SplitN(line_arr[1], "\t", 3)

		if len(insn_arr) > 2 {
			sym := elf.Symbol{Name: df.name, Value: uint64(df.start)}
			dl := p.ops.parseInsn(insn_arr[2], &sym)
			dl.offset, err = scv.ParseUint(line_arr[0], 16, 64)
			dl.opcode = insn_arr[1]

			df.insn = append(df.insn, dl)

			if lastOffset < dl.offset {
				lastOffset = dl.offset
			}
		} else {
			// leftover from the previous insn, append to it
			if len(df.insn) > 0 {
				last_dl := df.insn[len(df.insn)-1]
				last_dl.opcode += insn_arr[1]
			}
		}
	}

	for i, dl := range df.insn {
		if dl.optype == OPTYPE_INFO && i+1 < len(df.insn) &&
			df.insn[i+1].optype != OPTYPE_INFO {
			// use same offset (for arrow handling)
			dl.offset = df.insn[i+1].offset
		}
	}

	return df
}

func parseObjdump(p *DasParser, rc io.ReadCloser) {
	//var filename, format string
	var line string
	var err error
	var printed bool

	br := bufio.NewReader(rc)
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			break
		}

		parsedLines += 1

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
			fn := parseFunction(p, br, func_line[1], func_line[0])
			if fn != nil {
				csect.start++ // abuse it as function count
				funcs = append(funcs, fn)
			}
			if parsedLines > hugeOutput {
				fmt.Printf("\rParsing objdump output... %10d lines", parsedLines)
				printed = true
			}
		default:
		}
	}

	if printed {
		fmt.Println(".  Done.")
	}
}

func parseStrings(r io.Reader) {
	var line string
	var err error
	var ofs uint64

	strs = make(map[uint64]string)
	br := bufio.NewReader(r)

	for {
		line, err = br.ReadString('\n')
		if err != nil {
			break
		}

		data := str.SplitN(str.TrimSpace(line), " ", 2)
		if len(data) == 1 {
			continue
		}

		ofs, err = scv.ParseUint(data[0], 16, 64)
		strs[ofs] = data[1]

		parsedLines++
		if parsedLines > hugeOutput {
			fmt.Printf("\rLoading strings in binary.... %10d", parsedLines)
		}
	}
}

func lookupStrings(comment string, ignoreCode bool) string {
	cmt := str.Split(comment, " ")
	offset, err := scv.ParseUint(cmt[0], 16, 64)

	if err != nil {
		return comment
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

func runCommand(name string, args ...string) (*exec.Cmd, io.ReadCloser, error) {
	cmd := exec.Command(name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return cmd, nil, err
	}

	if err := cmd.Start(); err != nil {
		return cmd, nil, err
	}

	return cmd, stdout, nil
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
