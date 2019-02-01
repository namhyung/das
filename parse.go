package main

import (
	"debug/elf"
	"fmt"
	gcs "github.com/bnagy/gapstone"
	"log"
	scv "strconv"
	str "strings"
)

type Decoder interface {
	Objdump(df *DasFunc, line string)
	Capstone(insn gcs.Instruction, sym elf.Symbol) *DasLine
	ParsePLT(cap *CapstoneParser)
}

type X86Decoder struct {
}

func (d X86Decoder) Objdump(df *DasFunc, line string) {
	//  offset      opcode                mnemonic  args
	//          [TAB]                   [TAB]
	//   4aeba0:	64 48 8b 0c 25 f8 ff 	mov    %fs:0xfffffffffffffff8,%rcx
	//   4aeba7:	ff ff
	//   4aeba9:	48 8d 44 24 c8       	lea    -0x38(%rsp),%rax
	//   4aeefe:	48 3b 41 10          	cmp    0x10(%rcx),%rax
	//   4aef02:	0f 86 f6 01 00 00    	jbe    4af0fe <main.main+0x20e>

	line_arr := str.SplitN(line, ":", 2)
	insn_arr := str.Split(line_arr[1], "\t")

	dl := new(DasLine)
	dl.offset, _ = scv.ParseInt(line_arr[0], 16, 64)
	dl.opcode = insn_arr[1]

	if len(insn_arr) <= 2 {
		// leftover from the previous insn, append to it
		last_dl := df.insn[len(df.insn)-1]
		last_dl.opcode += dl.opcode
		return
	}

	dl.rawline = insn_arr[2]
	insn := str.SplitN(insn_arr[2], " ", 2)
	dl.mnemonic = insn[0]

	if str.HasPrefix(dl.mnemonic, "ret") {
		dl.optype = OPTYPE_RETURN
	}

	if len(insn) == 1 {
		df.insn = append(df.insn, dl)
		return
	}

	dl.args = str.TrimSpace(insn[1])

	if str.Index(dl.args, "#") != -1 {
		tmp := str.Split(dl.args, "#")
		dl.args = str.TrimSpace(tmp[0])
		dl.comment = str.TrimSpace(tmp[1])
	}

	if str.HasPrefix(dl.mnemonic, "j") ||
		str.HasPrefix(dl.mnemonic, "call") {
		dl.optype = OPTYPE_BRANCH

		tmp := str.Split(dl.args, " ")
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

	df.insn = append(df.insn, dl)
}

func makeRawline(dl *DasLine, insn gcs.Instruction, comment string) {
	for _, x := range insn.Bytes {
		dl.rawline += fmt.Sprintf("%02x ", x)
	}
	for len(dl.rawline) < 30 {
		dl.rawline += "   "
	}
	dl.rawline += fmt.Sprintf("%-8s  %s", insn.Mnemonic, insn.OpStr)

	if comment != "" {
		dl.rawline += comment
	}
}

func (d X86Decoder) Capstone(insn gcs.Instruction, sym elf.Symbol) *DasLine {
	dl := new(DasLine)

	dl.offset = int64(insn.Address)
	dl.mnemonic = insn.Mnemonic
	dl.args = insn.OpStr

	comment := ""

	if str.HasPrefix(dl.mnemonic, "ret") {
		dl.optype = OPTYPE_RETURN
	} else if str.HasPrefix(dl.mnemonic, "j") ||
		str.HasPrefix(dl.mnemonic, "call") {
		dl.optype = OPTYPE_BRANCH

		if str.HasPrefix(dl.args, "0x") {
			target, _ := scv.ParseUint(insn.OpStr, 0, 64)
			dl.target = int64(target)

			if sym.Value <= target && target < sym.Value+sym.Size {
				dl.local = true
				dl.args = fmt.Sprintf("%#x", target-sym.Value)
			} else {
				if name, ok := syms[target]; ok {
					dl.args = fmt.Sprintf("%s", name)
					comment = fmt.Sprintf("   # %s", dl.args)
				} else if name, ok := relocs[target]; ok {
					dl.args = fmt.Sprintf("<%s>", name)
					comment = fmt.Sprintf("   # %s", dl.args)
				} else {
					dl.args = fmt.Sprintf("%#x", target)
				}
			}
		}
		if dl.args[0] == '*' && str.HasSuffix(dl.args, "(%rip)") {
			imm, _ := scv.ParseUint(dl.args[1:len(dl.args)-6], 0, 64)
			imm += uint64(insn.Address)
			imm += uint64(insn.Size)

			// update function name using reloc info
			if name, ok := relocs[imm]; ok {
				dl.args = fmt.Sprintf("<%s>", name)
				comment = fmt.Sprintf("   # %x %s", imm, dl.args)
			}
		}
	} else if str.HasPrefix(dl.mnemonic, "lea") {
		idx := str.Index(insn.OpStr, "(%rip)")

		if idx != -1 {
			imm, _ := scv.ParseUint(insn.OpStr[0:idx], 0, 64)
			imm += uint64(insn.Address)
			imm += uint64(insn.Size)

			if name, ok := syms[imm]; ok {
				comment = fmt.Sprintf("   # %x %s", imm, name)
			} else if name, ok := relocs[imm]; ok {
				comment = fmt.Sprintf("   # %x <%s>", imm, name)
			} else {
				comment = fmt.Sprintf("   # %x", imm)
			}
			dl.args += comment
		}
	}

	makeRawline(dl, insn, comment)

	return dl
}

func parseX86PLT0(cap *CapstoneParser, insns []gcs.Instruction) int {
	var idx int

	fn := new(DasFunc)
	fn.name = "<plt0>"
	fn.start = int64(insns[0].Address)

	funcs = append(funcs, fn)
	syms[uint64(fn.start)] = fn.name

	dl := cap.decoder.Capstone(insns[0], elf.Symbol{})
	fn.insn = append(fn.insn, dl)

	for idx = 1; insns[idx].Address & 0xf != 0; idx++ {
		dl = cap.decoder.Capstone(insns[idx], elf.Symbol{})
		fn.insn = append(fn.insn, dl)

		if str.HasPrefix(dl.mnemonic, "j") {
			dl.optype = OPTYPE_BRANCH
		}
	}

	return idx
}

func parseX86PLTEntry(cap *CapstoneParser, insns []gcs.Instruction, idx int) int {
	fn := new(DasFunc)
	fn.start = int64(insns[idx].Address)

	funcs = append(funcs, fn)

	for i := 0; i < 3; i++ {
		insn := insns[idx + i]

		if i == 0 && insn.OpStr[0] == '*' && str.HasSuffix(insn.OpStr, "(%rip)") {
			imm, _ := scv.ParseUint(insn.OpStr[1:len(insn.OpStr)-6], 0, 64)
			imm += uint64(insn.Address)
			imm += uint64(insn.Size)

			// update function name using reloc info
			if name, ok := relocs[imm]; ok {
				fn.name = fmt.Sprintf("<%s@plt>", name)
				syms[uint64(fn.start)] = fn.name
			}
		}

		dl := cap.decoder.Capstone(insn, elf.Symbol{})
		fn.insn = append(fn.insn, dl)
	}

	return 3
}

func (d X86Decoder) ParsePLT(cap *CapstoneParser) {
	for _, sec := range cap.elf.Sections {
		if sec.Name != ".plt" {
			continue
		}

		buf, err := sec.Data()
		if err != nil {
			log.Fatal(err)
		}

		insns, err := cap.engine.Disasm(buf, sec.Addr, 0)
		if err != nil {
			log.Fatal(err)
		}

		idx := parseX86PLT0(cap, insns)

		for idx < len(insns) {
			idx += parseX86PLTEntry(cap, insns, idx)
		}
		break
	}
}
