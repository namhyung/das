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

type CapstoneParser struct {
	decoder Decoder
	engine  gcs.Engine
	elf     *elf.File
	file    *os.File
}

func prepareCapstone(target string) *CapstoneParser {
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
	var d Decoder

	switch e.Machine {
	case elf.EM_X86_64:
		arch = gcs.CS_ARCH_X86
		mode = gcs.CS_MODE_64
		d = X86Decoder{}
	case elf.EM_386:
		arch = gcs.CS_ARCH_X86
		mode = gcs.CS_MODE_32
		d = X86Decoder{}
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

	return &CapstoneParser { d, engine, e, f }
}

func parseReloc(cap *CapstoneParser) {
	symtab, err := cap.elf.DynamicSymbols()
	if err != nil {
		log.Fatal(err)
	}

	for _, sec := range cap.elf.Sections {
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

			if cap.elf.Data == elf.ELFDATA2LSB {
				endian = binary.LittleEndian
			} else {
				endian = binary.BigEndian
			}

			if cap.elf.Class == elf.ELFCLASS64 {
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

func parseCapstone(cap *CapstoneParser) {
	symtab, err := cap.elf.Symbols()
	if err != nil {
		log.Fatal(err)
	}

	for _, sym := range symtab {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}
		syms[sym.Value] = fmt.Sprintf("<%s>", sym.Name)
	}

	parseReloc(cap)

	cap.decoder.ParsePLT(cap)

	for _, sym := range symtab {
		if elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
			continue
		}

		if sym.Size == 0 {
			continue
		}

		sec := cap.elf.Sections[sym.Section]
		buf, err := sec.Data()

		sym_start := sym.Value - sec.Addr;
		insns, err := cap.engine.Disasm(buf[sym_start:sym_start + sym.Size], sym.Value, 0)
		if err != nil {
			fmt.Printf("Capstone disasm failed for %s\n", sym.Name)
			continue
		}

		fn := new(DasFunc)
		fn.name = fmt.Sprintf("<%s>", sym.Name)
		fn.start = int64(sym.Value)

		for _, insn := range insns {
			dl := cap.decoder.Capstone(insn, sym)
			fn.insn = append(fn.insn, dl)

		}
		funcs = append(funcs, fn)
	}

	sort.Sort(FuncSlice(funcs))

	sects := cap.elf.Sections
	secidx := -1
	count := len(funcs)

	for i := 0; i < count; i++ {
		fn := funcs[i]
		addr := uint64(fn.start)

		if secidx == -1 || sects[secidx].Addr + sects[secidx].Size <= addr {
			for secidx++; secidx < len(sects); secidx++ {
				sec := sects[secidx]
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
