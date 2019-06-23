// +build !nocapstone

package main

import (
	"debug/elf"
	"fmt"
	gcs "github.com/bnagy/gapstone"
	"log"
	scv "strconv"
	str "strings"
)

type DasCapstoneOpsAArch64 struct {
	p *DasParser
}

func (o DasCapstoneOpsAArch64) parseInsn(instr interface{}, sym *elf.Symbol) *DasLine {
	dl := new(DasLine)

	insn := instr.(gcs.Instruction)
	dl.offset = int64(insn.Address)
	dl.mnemonic = insn.Mnemonic
	dl.args = insn.OpStr

	comment := ""

	if str.HasPrefix(dl.mnemonic, "b") {
		dl.optype = OPTYPE_BRANCH

		if str.HasPrefix(dl.args, "#0x") {
			target, _ := scv.ParseUint(insn.OpStr[1:], 0, 64)
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
				}
			}
		}
	} else if dl.mnemonic == "ret" {
		dl.optype = OPTYPE_RETURN
	}

	makeRawline(dl, insn, comment)

	return dl
}

func (o DasCapstoneOpsAArch64) parsePLT0(insns []gcs.Instruction) int {
	var idx int

	fn := new(DasFunc)
	fn.name = "<plt0>"
	fn.start = int64(insns[0].Address)

	funcs = append(funcs, fn)
	syms[uint64(fn.start)] = fn.name

	for idx = 0; idx < 8; idx++ {
		// it only has an indirect branch, so dummy symbol should be fine
		dl := o.parseInsn(insns[idx], &elf.Symbol{})

		fn.insn = append(fn.insn, dl)
	}

	return idx
}

func (o DasCapstoneOpsAArch64) parsePLTEntry(insns []gcs.Instruction, idx int) int {
	fn := new(DasFunc)
	fn.start = int64(insns[idx].Address)

	funcs = append(funcs, fn)

	var i int
	var addr uint64

	for i = 0; i < 4; i++ {
		insn := &insns[idx+i]

		// it only has an indirect branch, so dummy symbol should be fine
		dl := o.parseInsn(*insn, &elf.Symbol{})

		// extract base page address  (ex. ADRP x16, 11000)
		if i == 0 {
			op := insn.Arm64.Operands[1]
			if op.Type == gcs.ARM64_OP_IMM {
				addr = uint64(op.Imm)
			}
		}

		// add offset in the page  (ex. LDR x17, [x16, #0x18])
		if i == 1 {
			op := insn.Arm64.Operands[1]
			if op.Type == gcs.ARM64_OP_MEM {
				addr += uint64(op.Mem.Disp)

				// update function name using reloc info
				if name, ok := relocs[addr]; ok {
					fn.name = fmt.Sprintf("<%s@plt>", name)
					syms[uint64(fn.start)] = fn.name

					comment := fmt.Sprintf("   # %x %s", addr, fn.name)
					dl.args += comment
				}
			}
		}

		fn.insn = append(fn.insn, dl)
	}

	return 4
}

func (o DasCapstoneOpsAArch64) parsePLT() {
	for _, sec := range o.p.elf.Sections {
		if sec.Name != ".plt" {
			continue
		}

		buf, err := sec.Data()
		if err != nil {
			log.Fatal(err)
		}

		insns, err := o.p.engine.Disasm(buf, sec.Addr, 0)
		if err != nil {
			log.Fatal(err)
		}

		idx := o.parsePLT0(insns)

		for idx < len(insns) {
			idx += o.parsePLTEntry(insns, idx)
		}
		break
	}
}

func (o DasCapstoneOpsAArch64) describe(insn *DasLine) string {
	return describeAArch64Insn(insn.mnemonic, insn.args)
}

func getCapstoneOpsAArch64(p *DasParser) DasArchOps {
	return DasCapstoneOpsAArch64{p}
}
