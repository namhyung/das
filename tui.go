/*
 * DAS - DisASsembler (not for MB)
 *
 * Copyright (C) 2017-2018  Namhyung Kim <namhyung@gmail.com>
 *
 * Released under MIT license.
 */
package main

import (
	"fmt"
	tui "github.com/gizak/termui"
)

type DasView struct {
	tui.Block // embedded

	fg_normal tui.Attribute
	bg_normal tui.Attribute
	fg_focus  tui.Attribute
	bg_focus  tui.Attribute

	top  int
	cur  int
	off  int64
	raw  bool
	miw  int // max insn width
	line []interface{}
	msg  func(interface{}) string
	stat func(interface{}) string
}

type DasStatus struct {
	tui.Block // embedded

	fg   tui.Attribute
	bg   tui.Attribute
	line string
}

var (
	cv *DasView   // current viewer
	sl *DasStatus // status line
)

func funcMsg(arg interface{}) string {
	df := arg.(*DasFunc)
	if df.sect {
		return "section: " + df.name
	} else {
		return fmt.Sprintf("   %x: %s", df.start, df.name)
	}
}

func insnMsg(arg interface{}) string {
	var ls string

	dl := arg.(*DasLine)
	if cv.raw {
		ls = fmt.Sprintf("  %4x:  %-*s   %s",
			dl.offset, cv.miw, dl.opcode, dl.rawline)
	} else {
		ls = fmt.Sprintf("  %4x:  %-7s   %s",
			dl.offset-cv.off, dl.mnemonic, dl.args)

		if len(dl.comment) > 0 {
			ls += "   # "
			ls += dl.comment
		}
	}

	return ls
}

func funcStat(arg interface{}) string {
	df := arg.(*DasFunc)
	if df.sect {
		return "section: " + df.name
	} else {
		return fmt.Sprintf("function: %s", df.name)
	}
}

func insnStat(arg interface{}) string {
	dl := arg.(*DasLine)
	return "instruction: " + dl.mnemonic
}

func (dv *DasView) Buffer() tui.Buffer {
	buf := dv.Block.Buffer()

	var fg, bg tui.Attribute

	x := 0
	y := 0

	for i, dl := range dv.line {
		if i < dv.top {
			continue
		}

		if i == dv.cur {
			fg = dv.fg_focus
			bg = dv.bg_focus
		} else {
			fg = dv.fg_normal
			bg = dv.bg_normal
		}

		ls := dv.msg(dl)
		cs := tui.DefaultTxBuilder.Build(ls, fg, bg)
		cs = tui.DTrimTxCls(cs, dv.Block.Width)

		x = 0
		for _, vv := range cs {
			w := vv.Width()
			buf.Set(x+1, y+1, vv)
			x += w
		}

		// fill cursor to the end
		if i == dv.cur {
			cs = tui.DefaultTxBuilder.Build(" ", fg, bg)
			for x < dv.Width-2 {
				for _, vv := range cs {
					w := vv.Width()
					buf.Set(x+1, y+1, vv)
					x += w
				}
			}
		}

		y++

		if y == dv.Height-2 {
			break
		}
	}

	sl.line = dv.stat(dv.line[dv.cur])
	return buf
}

func (ds *DasStatus) Buffer() tui.Buffer {
	buf := ds.Block.Buffer()

	cs := tui.DefaultTxBuilder.Build(ds.line, ds.fg, ds.bg)
	cs = tui.DTrimTxCls(cs, ds.Block.Width)

	x := 0
	for _, vv := range cs {
		w := vv.Width()
		buf.Set(x, ds.Y, vv)
		x += w
	}

	// fill status line to the end
	cs = tui.DefaultTxBuilder.Build(" ", ds.fg, ds.bg)
	for x < ds.Width {
		for _, vv := range cs {
			w := vv.Width()
			buf.Set(x, ds.Y, vv)
			x += w
		}
	}
	return buf
}

func up(dv *DasView) {
	if dv.cur == 0 {
		return
	}

	dv.cur--

	if dv.cur < dv.top {
		dv.top = dv.cur
	}
}

func down(dv *DasView) {
	if dv.cur == len(dv.line)-1 {
		return
	}

	dv.cur++

	if dv.top+dv.Height-2 == len(dv.line) {
		return
	}

	if dv.top+dv.Height-2 == dv.cur {
		dv.top++
	}
}

func pageUp(dv *DasView) {
	if dv.cur == 0 {
		return
	}

	if dv.cur != dv.top {
		dv.cur = dv.top
		return
	}

	dv.cur -= dv.Height - 2
	if dv.cur < 0 {
		dv.cur = 0
	}

	if dv.cur < dv.top {
		dv.top = dv.cur
	}
}

func pageDown(dv *DasView) {
	if dv.cur == len(dv.line)-1 {
		return
	}

	if dv.top+dv.Height-3 >= len(dv.line) {
		dv.cur = len(dv.line) - 1
	} else if dv.cur != dv.top+dv.Height-3 {
		dv.cur = dv.top + dv.Height - 3
	} else if dv.cur+dv.Height-2 >= len(dv.line) {
		dv.cur = len(dv.line) - 1
	} else {
		dv.cur += dv.Height - 2
	}

	dv.top = dv.cur - dv.Height + 3

	if dv.top < 0 {
		dv.top = 0
	}
}

func resize(dv *DasView) {
	dv.Width = tui.TermWidth()
	dv.Height = tui.TermHeight() - 1

	sl.Width = tui.TermWidth()
	sl.Height = 1
	sl.Y = tui.TermHeight() - 1
}

func render(dv *DasView) {
	tui.Render(dv) // it will update the status line (sl)
	tui.Render(sl)
}

func ShowTUI(file_name string) {
	if err := tui.Init(); err != nil {
		panic(err)
	}
	defer tui.Close()

	// function viewer
	fv := &DasView{
		Block:     *tui.NewBlock(),
		fg_normal: tui.ColorWhite,
		bg_normal: tui.ColorBlack,
		fg_focus:  tui.ColorYellow,
		bg_focus:  tui.ColorBlue,
		msg:       funcMsg,
		stat:      funcStat,
	}

	fv.line = make([]interface{}, len(funcs))
	for i, f := range funcs {
		fv.line[i] = f
	}

	// insn viewer
	iv := &DasView{
		Block:     *tui.NewBlock(),
		fg_normal: tui.ColorWhite,
		bg_normal: tui.ColorBlack,
		fg_focus:  tui.ColorYellow,
		bg_focus:  tui.ColorBlue,
		msg:       insnMsg,
		stat:      insnStat,
	}

	fv.BorderLabel = "DAS: " + file_name

	// status line
	sl = &DasStatus{
		Block: *tui.NewBlock(),
		fg:    tui.ColorBlack,
		bg:    tui.ColorWhite,
	}

	cv = fv
	resize(cv)
	render(cv)

	// handle key pressing
	tui.Handle("/sys/kbd/q", func(tui.Event) {
		// press q to quit
		tui.StopLoop()
	})

	tui.Handle("/sys/kbd/C-c", func(tui.Event) {
		// press Ctrl-C to quit
		tui.StopLoop()
	})

	tui.Handle("/sys/kbd/<up>", func(tui.Event) {
		up(cv)
		render(cv)
	})

	tui.Handle("/sys/kbd/<down>", func(tui.Event) {
		down(cv)
		render(cv)
	})

	tui.Handle("/sys/kbd/<previous>", func(e tui.Event) {
		pageUp(cv)
		render(cv)
	})

	tui.Handle("/sys/kbd/<next>", func(e tui.Event) {
		pageDown(cv)
		render(cv)
	})

	tui.Handle("/sys/wnd/resize", func(tui.Event) {
		resize(cv)
		render(cv)
	})

	tui.Handle("/sys/kbd/<enter>", func(tui.Event) {
		if cv != fv {
			return
		}

		if !funcs[fv.cur].sect {
			f := funcs[fv.cur]

			iv.top = 0
			iv.cur = 0
			iv.off = f.start
			iv.BorderLabel = f.name

			iv.line = make([]interface{}, len(f.insn))
			for i, l := range f.insn {
				iv.line[i] = l
			}

			cv = iv
			resize(cv)
			render(cv)
		}
	})

	tui.Handle("/sys/kbd/<escape>", func(tui.Event) {
		if cv != iv {
			return
		}
		cv = fv
		resize(cv)
		render(cv)
	})

	tui.Handle("/sys/kbd/v", func(tui.Event) {
		if cv != iv {
			return
		}

		// toggle to show raw opcode
		cv.raw = !cv.raw

		if cv.raw {
			cv.miw = 0
			for _, ln := range cv.line {
				insn := ln.(*DasLine)
				if len(insn.opcode) > cv.miw {
					cv.miw = len(insn.opcode)
				}
			}
		}

		resize(cv)
		render(cv)
	})

	tui.Loop()
}
