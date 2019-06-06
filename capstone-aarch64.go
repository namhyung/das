package main

import (
	"debug/elf"
	gcs "github.com/bnagy/gapstone"
)

type DasOpsAArch64 struct {
	p *DasParser
}

func (o DasOpsAArch64) parseInsn(insn gcs.Instruction, sym elf.Symbol) *DasLine {
	dl := new(DasLine)

	dl.offset = int64(insn.Address)
	dl.mnemonic = insn.Mnemonic
	dl.args = insn.OpStr

	makeRawline(dl, insn, "")

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
