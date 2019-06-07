package main

import (
	"debug/elf"
	"fmt"
	gcs "github.com/bnagy/gapstone"
	scv "strconv"
	str "strings"
)

type DasOpsAArch64 struct {
	p *DasParser
}

func (o DasOpsAArch64) parseInsn(insn gcs.Instruction, sym elf.Symbol) *DasLine {
	dl := new(DasLine)

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
	}

	makeRawline(dl, insn, comment)

	return dl
}

func (o DasOpsAArch64) parsePLT() {
}

func (o DasOpsAArch64) describe(insn *DasLine) string {
	return "xxx"
}

func getArchOpsAArch64(p *DasParser) DasArchOps {
	return DasOpsAArch64{p}
}
