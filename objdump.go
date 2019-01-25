package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	scv "strconv"
	str "strings"
)

func parseFunction(b *bytes.Buffer, d Decoder, name, offset string) *DasFunc {
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

		d.Objdump(df, line)

		last_dl := df.insn[len(df.insn)-1]

		if lastOffset < last_dl.offset {
			lastOffset = last_dl.offset
		}
	}

	return df
}

func parseObjdump(b *bytes.Buffer) {
	//var filename, format string
	var line string
	var err error
	var d Decoder

	for {
		line, err = b.ReadString('\n')
		if err != nil {
			break
		}

		switch {
		case str.Contains(line, "file format "):
			// das:     file format elf64-x86-64
			//file_name := str.Split(line, ":")[0]
			file_format := str.Split(line, "file format ")[1]
			file_format = str.TrimRight(file_format, "\n")

			if file_format == "elf64-x86-64" {
				d = X86Decoder{}
			} else {
				panic(fmt.Sprintf("Unsupported architecture: %s", file_format))
			}
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
			fn := parseFunction(b, d, func_line[1], func_line[0])
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
