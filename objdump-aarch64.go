package main

import (
	"debug/elf"
	"fmt"
	scv "strconv"
	str "strings"
)

type DasOpsAArch64 struct {
	p *DasParser
}

var (
	adrpReg string
	adrpOff uint64
)

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

func (o DasOpsAArch64) parseInsn(insn interface{}, sym *elf.Symbol) *DasLine {
	dl := new(DasLine)

	raw_line := insn.(string)

	tmp := str.SplitN(raw_line, "\t", 2)
	dl.mnemonic = str.TrimSpace(tmp[0])

	// TUI cannot print TAB so align it manually
	dl.rawline = fmt.Sprintf("%-8s", dl.mnemonic)

	if str.HasPrefix(dl.mnemonic, "ret") {
		dl.optype = OPTYPE_RETURN
	}

	if len(tmp) == 1 {
		return dl
	}

	dl.args = str.TrimSpace(tmp[1])
	dl.rawline += dl.args

	if str.Contains(dl.args, "//") {
		tmp = str.Split(dl.args, "//")
		dl.args = str.TrimSpace(tmp[0])
		dl.comment = str.TrimSpace(tmp[1])
	}

	if str.HasPrefix(dl.mnemonic, "b") {
		dl.optype = OPTYPE_BRANCH

		tmp = str.SplitN(dl.args, " ", 2)
		if len(tmp) == 2 {
			dl.target, _ = scv.ParseUint(tmp[0], 16, 64)
			dl.args = tmp[1]

			// if it's a jump in a same function, just save the offset
			if str.HasPrefix(dl.args, sym.Name[0:len(sym.Name)-1]) &&
				(dl.args[len(sym.Name)-1] == '+' ||
					dl.args[len(sym.Name)-1] == '>') {
				dl.args = fmt.Sprintf("%#x", dl.target-uint64(sym.Value))
				dl.local = true
			}
		}
	}

	if dl.mnemonic == "cbz" || dl.mnemonic == "cbnz" {
		dl.optype = OPTYPE_BRANCH

		tmp = str.SplitN(dl.args, " ", 3)
		if len(tmp) == 3 {
			dl.target, _ = scv.ParseUint(tmp[1], 16, 64)
			dl.args = tmp[2]

			// if it's a jump in a same function, just save the offset
			if str.HasPrefix(dl.args, sym.Name[0:len(sym.Name)-1]) &&
				(dl.args[len(sym.Name)-1] == '+' ||
					dl.args[len(sym.Name)-1] == '>') {
				dl.args = fmt.Sprintf("%s %#x", tmp[0], dl.target-uint64(sym.Value))
				dl.local = true
			}
		}
	}

	if adrpOff != 0 && (dl.mnemonic == "add" || dl.mnemonic == "ldr" || dl.mnemonic == "str") {
		if str.Contains(dl.args, adrpReg) {
			if idx := str.Index(dl.args, "#"); idx > 0 {
				off, err := scv.ParseUint(dl.args[idx+1:], 0, 64)
				if err != nil && str.HasSuffix(dl.args[idx+1:], "]") {
					addrStr := dl.args[idx+1:]
					off, _ = scv.ParseUint(addrStr[:len(addrStr)-1], 0, 64)
				}

				if sym := lookupSymbols(adrpOff+off, o.p); sym != "" {
					dl.comment = fmt.Sprintf("0x%-8x  %s", adrpOff+off, sym)
				} else {
					offStr := fmt.Sprintf("0x%x", adrpOff+off)
					dl.comment = lookupStrings(o.p, offStr, true)
				}
			}
		}
	}

	if dl.mnemonic == "adrp" {
		tmp = str.SplitN(dl.args, " ", 3)
		if len(tmp) == 3 {
			adrpReg = tmp[0]
			adrpOff, _ = scv.ParseUint(tmp[1], 16, 64)

			// ignore dummy symbol
			dl.args = tmp[0] + " " + tmp[1]
		}
	} else {
		adrpOff = 0
		adrpReg = ""
	}

	return dl
}

func (o DasOpsAArch64) parsePLT() {
}

func (o DasOpsAArch64) describe(dl *DasLine) string {
	return describeAArch64Insn(dl.mnemonic, dl.args)
}

func getArchOpsAArch64(p *DasParser) DasArchOps {
	p.comment = "//"
	return DasOpsAArch64{p}
}
