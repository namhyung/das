package main

import (
	"debug/elf"
	"fmt"
	str "strings"
)

type DasOpsAArch64 struct {
	p *DasParser
}

func describeAArch64Insn(name, args string) string {
	// check core instructions
	desc := Insn_AArch64[name]
	if len(desc) > 0 {
		return desc
	}

	namelen := len(name)
	if name[namelen-1] == 's' {
		cname := name[:namelen-1]

		for _, csi := range CondSetInsn_AArch64 {
			if cname == csi {
				desc = Insn_AArch64[csi]
			}
		}
		if len(desc) > 0 {
			return fmt.Sprintf("%s, Set condition flags", desc)
		}
	}

	if str.HasPrefix(name, "b.") {
		for cc, cdesc := range Cond_AArch64 {
			if name[2:] == cc {
				return fmt.Sprintf("Branch If %s", cdesc)
			}
		}
	}

	// check Floating-Point and SIMD instructions
	desc = SIMDInsn_AArch64[name]
	if len(desc) > 0 {
		return desc
	}

	// check instructions with condition suffix
	if len(name) > 2 {
		cname := name[:namelen-2]
		for _, csi := range CondSIMDInsn_AArch64 {
			if cname == csi {
				desc = SIMDInsn_AArch64[csi]
			}
		}
		if len(desc) > 0 {
			for cc, cdesc := range Cond_AArch64 {
				if name[namelen-2:] == cc {
					return fmt.Sprintf("%s %s", desc, cdesc)
				}
			}
		}
	}

	return "unknown"
}

func (o DasOpsAArch64) parseInsn(insn interface{}, sym elf.Symbol) *DasLine {
	return &DasLine{}
}

func (o DasOpsAArch64) parsePLT() {
}

func (o DasOpsAArch64) describe(dl *DasLine) string {
	return describeAArch64Insn(dl.mnemonic, dl.args)
}

func getArchOpsAArch64(p *DasParser) DasArchOps {
	return DasOpsAArch64{p}
}
