package main

import (
	"debug/elf"
	"fmt"
	scv "strconv"
	str "strings"
)

type DasOpsX86 struct {
	p *DasParser
}

func describeX86Insn(name, args string) string {
	desc := Insn_x86_64[name]
	if len(desc) > 0 {
		return desc
	}

	// there are two kinds of 'movsd' instructions
	if name == "movsd" && str.Contains(args, "%xmm") {
		return "Move Scalar Double-FP Values  [SSE]"
	}

	// check 'LOCK' prefix
	if str.HasPrefix(name, "lock ") {
		return describeX86Insn(name[5:], args)
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

	namelen := len(name)
	iname := name[:namelen-1]
	suffix := name[namelen-1:]

	// if it has a size suffix (bwdlq), try to match again without it
	if size, ok := Size_x86_64[suffix]; ok {
		if name, ok2 := SizeInsn_x86_64[iname]; ok2 {
			return str.ReplaceAll(name, "${SIZE}", size)
		}

		if desc, ok2 := Insn_x86_64[iname]; ok2 {
			return desc
		}
	}

	return "unknown"
}

func (o DasOpsX86) parseInsn(insn interface{}, sym *elf.Symbol) *DasLine {
	dl := new(DasLine)

	raw_line := insn.(string)
	dl.rawline = raw_line

	tmp := str.SplitN(raw_line, " ", 2)
	dl.mnemonic = str.TrimSpace(tmp[0])

	if str.HasPrefix(dl.mnemonic, "ret") {
		dl.optype = OPTYPE_RETURN
	}

	if len(tmp) == 1 {
		return dl
	}

	dl.args = str.TrimSpace(tmp[1])

	if str.Contains(dl.args, "#") {
		tmp = str.Split(dl.args, "#")
		dl.args = str.TrimSpace(tmp[0])
		dl.comment = str.TrimSpace(tmp[1])
	}

	if str.HasPrefix(dl.mnemonic, "j") ||
		str.HasPrefix(dl.mnemonic, "call") {
		dl.optype = OPTYPE_BRANCH

		tmp = str.Split(dl.args, " ")
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

	return dl
}

func (o DasOpsX86) parsePLT() {
}

func (o DasOpsX86) describe(dl *DasLine) string {
	return describeX86Insn(dl.mnemonic, dl.args)
}

func getArchOpsX86(p *DasParser) DasArchOps {
	return DasOpsX86{p}
}
