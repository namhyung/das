// +build capstone

package main

import (
	"debug/elf"
	"fmt"
	gcs "github.com/bnagy/gapstone"
	"log"
	scv "strconv"
	str "strings"
)

type DasCapstoneOpsX86 struct {
	p *DasParser
	e *gcs.Engine
}

func (o DasCapstoneOpsX86) parseInsn(instr interface{}, sym *elf.Symbol) *DasLine {
	dl := new(DasLine)

	insn := instr.(gcs.Instruction)
	dl.offset = uint64(insn.Address)
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
			dl.target = target

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

func parsePLT0(insns []gcs.Instruction) int {
	var idx int

	fn := new(DasFunc)
	fn.name = "<plt0>"
	fn.start = uint64(insns[0].Address)

	funcs = append(funcs, fn)
	syms[uint64(fn.start)] = fn.name

	dl := new(DasLine)
	dl.offset = uint64(insns[0].Address)
	dl.mnemonic = insns[0].Mnemonic
	dl.args = insns[0].OpStr
	makeRawline(dl, insns[0], "")

	fn.insn = append(fn.insn, dl)

	for idx = 1; insns[idx].Address&0xf != 0; idx++ {
		dl = new(DasLine)
		dl.offset = uint64(insns[idx].Address)
		dl.mnemonic = insns[idx].Mnemonic
		dl.args = insns[idx].OpStr
		makeRawline(dl, insns[idx], "")

		fn.insn = append(fn.insn, dl)

		if str.HasPrefix(dl.mnemonic, "j") {
			dl.optype = OPTYPE_BRANCH
		}
	}

	return idx
}

func parsePLTEntry(insns []gcs.Instruction, idx int) int {
	fn := new(DasFunc)
	fn.start = uint64(insns[idx].Address)

	funcs = append(funcs, fn)

	for i := 0; i < 3; i++ {
		dl := new(DasLine)
		dl.offset = uint64(insns[idx+i].Address)
		dl.mnemonic = insns[idx+i].Mnemonic
		dl.args = insns[idx+i].OpStr

		comment := ""
		fn.insn = append(fn.insn, dl)

		if i == 0 && dl.args[0] == '*' && str.HasSuffix(dl.args, "(%rip)") {
			dl.optype = OPTYPE_BRANCH

			imm, _ := scv.ParseUint(dl.args[1:len(dl.args)-6], 0, 64)
			imm += uint64(insns[idx+i].Address)
			imm += uint64(insns[idx+i].Size)

			// update function name using reloc info
			if name, ok := relocs[imm]; ok {
				fn.name = fmt.Sprintf("<%s@plt>", name)
				syms[uint64(fn.start)] = fn.name
				comment = fmt.Sprintf("   # %x %s", imm, fn.name)
				dl.args += comment
			}
		}

		if i == 2 {
			dl.optype = OPTYPE_BRANCH
			dl.target = uint64(insns[0].Address)
			dl.args = "<plt0>"
		}

		makeRawline(dl, insns[idx+i], comment)
	}

	return 3
}

func (o DasCapstoneOpsX86) parsePLT() {
	for _, sec := range o.p.elf.Sections {
		if sec.Name != ".plt" {
			continue
		}

		buf, err := sec.Data()
		if err != nil {
			log.Fatal(err)
		}

		insns, err := o.e.Disasm(buf, sec.Addr, 0)
		if err != nil {
			log.Fatal(err)
		}

		idx := parsePLT0(insns)

		for idx < len(insns) {
			idx += parsePLTEntry(insns, idx)
		}
		break
	}
}

func (o DasCapstoneOpsX86) describe(dl *DasLine) string {
	return describeX86Insn(dl.mnemonic, dl.args)
}

func getCapstoneOpsX86(p *DasParser) DasArchOps {
	return DasCapstoneOpsX86{p, p.engine.(*gcs.Engine)}
}
