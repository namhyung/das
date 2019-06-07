package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	scv "strconv"
	str "strings"
)

func parseObjdumpInsn(df *DasFunc, dl *DasLine, raw_line string) {
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
			parseObjdumpInsn(df, dl, insn_arr[2])

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

func parseObjdump(b *bytes.Buffer) {
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
			fn := parseFunction(b, func_line[1], func_line[0])
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
