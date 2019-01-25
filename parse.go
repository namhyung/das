package main

import (
	"fmt"
	scv "strconv"
	str "strings"
)

type Decoder interface {
	Objdump(df *DasFunc, line string)
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
