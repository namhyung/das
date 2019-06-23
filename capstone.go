// +build !nocapstone

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	gcs "github.com/bnagy/gapstone"
	"log"
	"sort"
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

func prepareCapstone(p *DasParser) {
	var arch int
	var mode uint

	switch p.elf.Machine {
	case elf.EM_X86_64:
		arch = gcs.CS_ARCH_X86
		mode = gcs.CS_MODE_64
		p.ops = getCapstoneOpsX86(p)
	case elf.EM_386:
		arch = gcs.CS_ARCH_X86
		mode = gcs.CS_MODE_32
	case elf.EM_ARM:
		arch = gcs.CS_ARCH_ARM
		mode = gcs.CS_MODE_ARM
	case elf.EM_AARCH64:
		arch = gcs.CS_ARCH_ARM64
		mode = gcs.CS_MODE_ARM
		p.ops = getCapstoneOpsAArch64(p)
	default:
		log.Fatal("Unsupported Architect\n")
	}

	engine, err := gcs.New(arch, mode)
	if err != nil {
		log.Fatal(err)
	}

	engine.SetOption(gcs.CS_OPT_SYNTAX, gcs.CS_OPT_SYNTAX_ATT)
	engine.SetOption(gcs.CS_OPT_DETAIL, gcs.CS_OPT_ON)

	p.engine = &engine
}

func makeRawline(dl *DasLine, insn gcs.Instruction, comment string) {
	for _, x := range insn.Bytes {
		dl.rawline += fmt.Sprintf("%02x ", x)
	}
	for len(dl.rawline) < 30 {
		dl.rawline += "   "
	}
	dl.rawline += fmt.Sprintf("%-8s  %s", insn.Mnemonic, insn.OpStr)

	if comment != "" {
		dl.rawline += comment
	}
}

func parseReloc(p *DasParser) {
	symtab, err := p.elf.DynamicSymbols()
	if err != nil {
		log.Fatal(err)
	}

	for _, sec := range p.elf.Sections {
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

			if p.elf.Data == elf.ELFDATA2LSB {
				endian = binary.LittleEndian
			} else {
				endian = binary.BigEndian
			}

			if p.elf.Class == elf.ELFCLASS64 {
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

func parseCapstoneFunc(p *DasParser, fn *DasFunc) {
	sym := fn.sym
	sec := p.elf.Sections[sym.Section]
	buf, err := sec.Data()

	sym_start := sym.Value - sec.Addr
	insns, err := p.engine.Disasm(buf[sym_start:sym_start+sym.Size], sym.Value, 0)
	if err != nil {
		fmt.Printf("Capstone disasm failed for %s\n", sym.Name)
		return
	}

	for _, insn := range insns {
		dl := p.ops.parseInsn(insn, sym)
		fn.insn = append(fn.insn, dl)
	}
}

func parseCapstone(p *DasParser) {
	symtab, err := p.elf.Symbols()
	if err != nil {
		log.Fatal(err)
	}

	for _, sym := range symtab {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}
		syms[sym.Value] = fmt.Sprintf("<%s>", sym.Name)
	}

	parseReloc(p)

	p.ops.parsePLT()

	for _, sym := range symtab {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}

		if sym.Size == 0 {
			continue
		}

		fn := new(DasFunc)
		fn.name = fmt.Sprintf("<%s>", sym.Name)
		fn.start = int64(sym.Value)
		fn.sym = sym

		parseCapstoneFunc(p, fn)

		funcs = append(funcs, fn)
	}

	sort.Sort(FuncSlice(funcs))

	secidx := -1
	count := len(funcs)

	for i := 0; i < count; i++ {
		fn := funcs[i]
		addr := uint64(fn.start)

		if secidx == -1 || p.elf.Sections[secidx].Addr+p.elf.Sections[secidx].Size <= addr {
			for secidx++; secidx < len(p.elf.Sections); secidx++ {
				sec := p.elf.Sections[secidx]
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
