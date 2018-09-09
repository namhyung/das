package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	gcs "github.com/bnagy/gapstone"
	"log"
	"os"
	"sort"
	scv "strconv"
	str "strings"
)

var (
	syms   map[uint64]string
	relocs map[uint64]string
)

func init() {
	syms = make(map[uint64]string)
	relocs = make(map[uint64]string)
}

type FuncSlice []*DasFunc

func (arr FuncSlice) Len() int {
	return len(arr)
}

func (arr FuncSlice) Less(i, j int) bool {
	return arr[i].start < arr[j].start
}

func (arr FuncSlice) Swap(i, j int) {
	arr[i], arr[j] = arr[j], arr[i]
}

func prepareCapstone(target string) (*os.File, *elf.File, gcs.Engine) {
	f, err := os.Open(target)
	if err != nil {
		log.Fatal(err)
	}

	e, err := elf.NewFile(f)
	if err != nil {
		log.Fatal(err)
	}

	var arch int
	var mode uint

	switch e.Machine {
	case elf.EM_X86_64:
		arch = gcs.CS_ARCH_X86
		mode = gcs.CS_MODE_64
	case elf.EM_386:
		arch = gcs.CS_ARCH_X86
		mode = gcs.CS_MODE_32
	case elf.EM_ARM:
		arch = gcs.CS_ARCH_ARM
		mode = gcs.CS_MODE_ARM
	case elf.EM_AARCH64:
		arch = gcs.CS_ARCH_ARM64
		mode = gcs.CS_MODE_ARM
	default:
		log.Fatal("Unsupported Architect\n")
	}

	engine, err := gcs.New(arch, mode)
	if err != nil {
		log.Fatal(err)
	}

	engine.SetOption(gcs.CS_OPT_SYNTAX, gcs.CS_OPT_SYNTAX_ATT)

	return f, e, engine
}

func makeRawline(dl *DasLine, insn gcs.Instruction) {
	for _, x := range insn.Bytes {
		dl.rawline += fmt.Sprintf("%02x ", x)
	}
	for len(dl.rawline) < 30 {
		dl.rawline += "   "
	}
	dl.rawline += fmt.Sprintf("%-8s  %s", dl.mnemonic, dl.args)
}

func parseCapstoneInsn(insn gcs.Instruction, sym elf.Symbol) *DasLine {
	dl := new(DasLine)

	dl.offset = int64(insn.Address)
	dl.mnemonic = insn.Mnemonic
	dl.args = insn.OpStr

	makeRawline(dl, insn)

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
					dl.args = fmt.Sprintf("<%s>", name)
				} else if name, ok := relocs[target]; ok {
					dl.args = fmt.Sprintf("<%s>", name)
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
			}
		}
	} else if str.HasPrefix(dl.mnemonic, "lea") {
		idx := str.Index(insn.OpStr, "(%rip)")

		if idx != -1 {
			imm, _ := scv.ParseUint(insn.OpStr[0:idx], 0, 64)
			imm += uint64(insn.Address)
			imm += uint64(insn.Size)

			if name, ok := syms[imm]; ok {
				dl.args += fmt.Sprintf("   # %x <%s>", imm, name)
			} else if name, ok := relocs[imm]; ok {
				dl.args += fmt.Sprintf("   # %x <%s>", imm, name)
			} else {
				dl.args += fmt.Sprintf("   # %x", imm)
			}
		}
	}

	return dl
}

func parseReloc(f *os.File, e *elf.File, engine gcs.Engine) {
	symtab, err := e.DynamicSymbols()
	if err != nil {
		log.Fatal(err)
	}

	for _, sec := range e.Sections {
		if sec.Type != elf.SHT_REL && sec.Type != elf.SHT_RELA {
			continue
		}

		buf, err := sec.Data()
		if err != nil {
			log.Fatal(err)
		}

		esize := int(sec.Entsize)
		for i := 0; i < len(buf); i += esize {
			var data *bytes.Buffer
			var endian binary.ByteOrder
			var offset uint64
			var idx uint32

			data = bytes.NewBuffer(buf[i : i+esize])

			if e.Data == elf.ELFDATA2LSB {
				endian = binary.LittleEndian
			} else {
				endian = binary.BigEndian
			}

			if e.Class == elf.ELFCLASS64 {
				if sec.Type == elf.SHT_RELA {
					reloc := elf.Rela64{}
					binary.Read(data, endian, &reloc)
					idx = elf.R_SYM64(reloc.Info)
					offset = reloc.Off
				} else {
					reloc := elf.Rel64{}
					binary.Read(data, endian, &reloc)
					idx = elf.R_SYM64(reloc.Info)
					offset = reloc.Off
				}
			} else {
				if sec.Type == elf.SHT_RELA {
					reloc := elf.Rela32{}
					binary.Read(data, endian, &reloc)
					idx = elf.R_SYM32(reloc.Info)
					offset = uint64(reloc.Off)
				} else {
					reloc := elf.Rel32{}
					binary.Read(data, endian, &reloc)
					idx = elf.R_SYM32(reloc.Info)
					offset = uint64(reloc.Off)
				}
			}

			if idx == 0 {
				continue
			}
			relocs[offset] = symtab[idx-1].Name
		}
	}
}

func parsePLT0(insns []gcs.Instruction) int {
	var idx int

	fn := new(DasFunc)
	fn.name = "plt0"
	fn.start = int64(insns[0].Address)

	funcs = append(funcs, fn)
	syms[uint64(fn.start)] = fn.name

	dl := new(DasLine)
	dl.offset = int64(insns[0].Address)
	dl.mnemonic = insns[0].Mnemonic
	dl.args = insns[0].OpStr
	makeRawline(dl, insns[0])

	fn.insn = append(fn.insn, dl)

	for idx = 1; insns[idx].Address&0xf != 0; idx++ {
		dl = new(DasLine)
		dl.offset = int64(insns[idx].Address)
		dl.mnemonic = insns[idx].Mnemonic
		dl.args = insns[idx].OpStr
		makeRawline(dl, insns[idx])

		fn.insn = append(fn.insn, dl)

		if str.HasPrefix(dl.mnemonic, "j") {
			dl.optype = OPTYPE_BRANCH
		}
	}

	return idx
}

func parsePLTEntry(insns []gcs.Instruction, idx int) int {
	fn := new(DasFunc)
	fn.start = int64(insns[idx].Address)

	funcs = append(funcs, fn)

	for i := 0; i < 3; i++ {
		dl := new(DasLine)
		dl.offset = int64(insns[idx+i].Address)
		dl.mnemonic = insns[idx+i].Mnemonic
		dl.args = insns[idx+i].OpStr
		makeRawline(dl, insns[idx+i])

		fn.insn = append(fn.insn, dl)

		if i == 0 && dl.args[0] == '*' && str.HasSuffix(dl.args, "(%rip)") {
			dl.optype = OPTYPE_BRANCH

			imm, _ := scv.ParseUint(dl.args[1:len(dl.args)-6], 0, 64)
			imm += uint64(insns[idx+i].Address)
			imm += uint64(insns[idx+i].Size)

			// update function name using reloc info
			if name, ok := relocs[imm]; ok {
				fn.name = fmt.Sprintf("%s@plt", name)
				syms[uint64(fn.start)] = fn.name
				dl.args += fmt.Sprintf("   # %x <%s>", imm, fn.name)
			}
		}

		if i == 2 {
			dl.optype = OPTYPE_BRANCH
			dl.target = int64(insns[0].Address)
			dl.args = "<plt0>"
		}
	}

	return 3
}

func parsePLT(f *os.File, e *elf.File, engine gcs.Engine) {
	for _, sec := range e.Sections {
		if sec.Name != ".plt" {
			continue
		}

		buf, err := sec.Data()
		if err != nil {
			log.Fatal(err)
		}

		insns, err := engine.Disasm(buf, sec.Addr, 0)
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

func parseCapstone(f *os.File, e *elf.File, engine gcs.Engine) {
	symtab, err := e.Symbols()
	if err != nil {
		log.Fatal(err)
	}

	for _, sym := range symtab {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}
		syms[sym.Value] = sym.Name
	}

	parseReloc(f, e, engine)
	parsePLT(f, e, engine)

	for _, sym := range symtab {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}

		if sym.Size == 0 {
			continue
		}

		buf := make([]byte, sym.Size)
		sec := e.Sections[sym.Section]

		_, err = f.ReadAt(buf, int64(sym.Value-sec.Addr+sec.Offset))
		if err != nil {
			log.Fatal(err)
		}

		insns, err := engine.Disasm(buf, sym.Value, 0)
		if err != nil {
			log.Fatal(err)
		}

		fn := new(DasFunc)
		fn.name = sym.Name
		fn.start = int64(sym.Value)

		for _, insn := range insns {
			dl := parseCapstoneInsn(insn, sym)
			fn.insn = append(fn.insn, dl)

		}
		funcs = append(funcs, fn)
	}

	sort.Sort(FuncSlice(funcs))

	secidx := -1
	count := len(funcs)

	for i := 0; i < count; i++ {
		fn := funcs[i]
		addr := uint64(fn.start)

		if secidx == -1 || e.Sections[secidx].Addr+e.Sections[secidx].Size <= addr {
			for secidx++; secidx < len(e.Sections); secidx++ {
				sec := e.Sections[secidx]
				if (sec.Flags & elf.SHF_EXECINSTR) == 0 {
					continue
				}
				if sec.Addr <= addr && addr < sec.Addr+sec.Size {
					fn := new(DasFunc)
					fn.name = sec.Name
					fn.sect = true
					csect = fn

					tmp := append([]*DasFunc{fn}, funcs[i:]...)
					funcs = append(funcs[:i], tmp...)
					count++
					i++
					break
				}
			}
		}
		csect.start++
	}
}
