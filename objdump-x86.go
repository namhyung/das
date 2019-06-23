package main

import (
	"debug/elf"
	"fmt"
	str "strings"
)

type DasOpsX86 struct {
	p *DasParser
}

func describeX86Insn(name, args string) string {
	desc := Insn_x86_64[name]
	if len(desc) > 0 {
		// there are two kinds of 'movsd' instructios
		if name == "movsd" && str.Contains(args, "%xmm") {
			desc = "Move Scalar Double-Precision Floating-Point Values"
		}

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

	return "unknown"
}

func (o DasOpsX86) parseInsn(insn interface{}, sym *elf.Symbol) *DasLine {
	return &DasLine{}
}

func (o DasOpsX86) parsePLT() {
}

func (o DasOpsX86) describe(dl *DasLine) string {
	return describeX86Insn(dl.mnemonic, dl.args)
}

func getArchOpsX86(p *DasParser) DasArchOps {
	return DasOpsX86{p}
}
