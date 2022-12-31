package main

import (
	"bufio"
	"debug/elf"
	"fmt"
	"io"
	"log"
	"os/exec"
	"sort"
	scv "strconv"
	str "strings"

	"github.com/ianlancetaylor/demangle"
)

const (
	hugeOutput int = 300000
)

var (
	parsedLines int
)

func parseFunction(p *DasParser, br *bufio.Reader, df *DasFunc) {
	var currFunc string

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
}

func parseObjdump(p *DasParser, df *DasFunc, rc io.ReadCloser) {
	//var filename, format string
	var printed bool

	br := bufio.NewReader(rc)
	for {
		line, err := br.ReadString('\n')
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
			if df != nil {
				// if it already has 'df', that means it has the
				// full list of sections and functions.
				// No need to create a section.
				break
			}
			sect := new(DasFunc)
			sect.name = str.Split(line, "section ")[1]
			sect.name = str.TrimRight(sect.name, ":\n")
			sect.sect = true
			funcs = append(funcs, sect)
			csect = sect
		case str.HasSuffix(line, ">:\n"):
			// 00000000004aeba0 <main.main>:
			if df == nil {
				func_line := str.SplitN(line, " ", 2)
				df = new(DasFunc)
				df.name = str.TrimRight(func_line[1], ":\n")
				df.start, err = scv.ParseUint(func_line[0], 16, 64)
				if err != nil {
					log.Println(err)
					break
				}
				csect.start++ // abuse it as function count
				funcs = append(funcs, df)
			}
			parseFunction(p, br, df)
			if !p.hasFns && parsedLines > hugeOutput {
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

func parseObjdumpFunc(p *DasParser, fn *DasFunc) {
	var idx int
	var nextFn *DasFunc

	// find index of current function
	idx = sort.Search(len(funcs), func(i int) bool {
		return !funcs[i].sect && funcs[i].start >= fn.start
	})

	// we actual need next function index
	idx++

	// find next function (skip sections)
	for idx < len(funcs) {
		if !funcs[idx].sect {
			nextFn = funcs[idx]
			break
		}
		idx++
	}

	args := []string{"-d", "-C"}
	if useInline {
		args = append(args, "-l", "--inlines")
	}
	args = append(args, "--start-address", fmt.Sprintf("0x%x", fn.start))
	if nextFn != nil {
		args = append(args, "--stop-address", fmt.Sprintf("0x%x", nextFn.start))
	}
	args = append(args, p.name)

	cmd, r, err := runCommand(objdump, args...)
	if err == nil {
		parseObjdump(p, fn, r)
	} else {
		dl := &DasLine{
			optype:   OPTYPE_INFO,
			mnemonic: "ERROR",
			args:     err.Error(),
			rawline:  fn.name + ": objdump error: " + err.Error(),
		}
		fn.insn = append(fn.insn, dl)
	}
	cmd.Wait()
}

type elfFunc struct {
	name  string
	start uint64
	idx   int
}
type efSlice []elfFunc

func (fns efSlice) Len() int {
	return len(fns)
}

func (fns efSlice) Swap(i, j int) {
	fns[i], fns[j] = fns[j], fns[i]
}

func (fns efSlice) Less(i, j int) bool {
	return fns[i].start < fns[j].start
}

func initFuncList(p *DasParser) {
	var funs []elfFunc

	symtab, err := p.elf.Symbols()
	if err != nil {
		log.Println(err)
		return
	}

	for _, sym := range symtab {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}

		if sym.Section == elf.SHN_UNDEF {
			continue
		}

		funs = append(funs, elfFunc{name: sym.Name, start: sym.Value, idx: int(sym.Section)})
	}

	// add PLT functions seperately as no symbols linked to them
	for i, sec := range p.elf.Sections {
		if sec.Name != ".plt" && sec.Name != ".plt.got" {
			continue
		}

		args := []string{"-d"}
		args = append(args, "--start-address", fmt.Sprintf("0x%x", sec.Addr))
		args = append(args, "--stop-address", fmt.Sprintf("0x%x", sec.Addr+sec.Size))
		args = append(args, p.name)

		cmd, r, err := runCommand("objdump", args...)
		if err != nil {
			continue
		}

		br := bufio.NewReader(r)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}

			// 00000000004aeba0 <main.main>:
			if !str.HasSuffix(line, ">:\n") {
				continue
			}

			func_line := str.SplitN(line, " ", 2)
			// trim < and > in the name
			name := str.TrimRight(func_line[1], ">:\n")[1:]
			start, err := scv.ParseUint(func_line[0], 16, 64)
			if err != nil {
				log.Println(err)
				continue
			}

			// first PLT entry has no associated function,
			// use the section name instead
			if sec.Name == ".plt" && sec.Addr == start {
				name = sec.Name
			}
			funs = append(funs, elfFunc{name: name, start: start, idx: i})
		}
		cmd.Wait()
	}

	idx := 0
	sort.Sort(efSlice(funs))

	// iterate functions and inject section
	for _, fn := range funs {
		if fn.idx != idx && fn.idx < len(p.elf.Sections) {
			ds := new(DasFunc)
			ds.sect = true
			ds.name = p.elf.Sections[fn.idx].Name
			funcs = append(funcs, ds)

			csect = ds
			idx = fn.idx
		}

		df := new(DasFunc)
		name, err := demangle.ToString(fn.name)
		if err != nil {
			name = fn.name
		}
		df.name = "<" + name + ">"
		df.start = fn.start
		funcs = append(funcs, df)

		// abuse 'start' of section as a function count
		if csect != nil {
			csect.start++
		}
	}

	p.hasFns = true
}

func initStrings(p *DasParser) {
	p.rodata = -1

	// save index and data of rodata section
	for i, sec := range p.elf.Sections {
		if sec.Name == ".rodata" {
			p.rodata = i
			data, err := sec.Data()
			if err == nil {
				p.strs = data
			}
			break
		}
	}

	strs = make(map[uint64]string)
}

func lookupStrings(p *DasParser, comment string) string {
	cmt := str.Split(comment, " ")

	offStr := cmt[0]
	if str.HasPrefix(offStr, "0x") {
		offStr = offStr[2:]
	}
	offset, err := scv.ParseUint(offStr, 16, 64)

	if err != nil {
		return comment
	}

	// check strs cache first
	strconst, ok := strs[offset]
	if ok {
		return fmt.Sprintf("%-8s  \"%s\"", cmt[0], strconst)
	}

	if p.rodata != -1 && p.strs != nil {
		rodata := p.elf.Sections[p.rodata]
		if rodata.Addr <= offset && offset < (rodata.Addr+rodata.Size) {
			var sb str.Builder

			for ofs := offset - rodata.Addr; ofs < rodata.Size; ofs++ {
				c := rune(p.strs[ofs])
				if !scv.IsPrint(c) {
					break
				}
				sb.WriteRune(c)
			}

			ret := sb.String()
			if len(ret) > 3 {
				// save the result to the cache
				strs[offset] = ret
				return fmt.Sprintf("%-8s  \"%s\"", cmt[0], ret)
			}
		}
	}
	return comment
}

func lookupSymbols(addr uint64, p *DasParser) string {
	symbols, _ := p.elf.Symbols()
	for _, sym := range symbols {
		if sym.Value <= addr && addr < sym.Value+sym.Size {
			if sym.Value == addr {
				return fmt.Sprintf("<%s>", sym.Name)
			} else {
				return fmt.Sprintf("<%s+%x>", sym.Name, addr-sym.Value)
			}
		}
	}

	symbols, _ = p.elf.DynamicSymbols()
	for _, sym := range symbols {
		if sym.Value <= addr && addr < sym.Value+sym.Size {
			if sym.Value == addr {
				return fmt.Sprintf("<%s>", sym.Name)
			} else {
				return fmt.Sprintf("<%s+%x>", sym.Name, addr-sym.Value)
			}
		}
	}

	return ""
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
