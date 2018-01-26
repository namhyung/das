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
	scv "strconv"
	str "strings"
)

type DasView struct {
	tui.Block // embedded

	fg_normal tui.Attribute
	bg_normal tui.Attribute
	fg_focus  tui.Attribute
	bg_focus  tui.Attribute

	top   int
	cur   int
	off   int64
	insn  bool
	raw   bool
	arrow bool
	miw   int // max insn width
	mow   int // max opcode width
	line  []interface{}
	msg   func(interface{}) string
	stat  func(interface{}) string
}

type DasStatus struct {
	tui.Block // embedded

	fg   tui.Attribute
	bg   tui.Attribute
	line string
}

type DasHist struct {
	fun  *DasFunc
	ftop int // fv.top
	fcur int // fv.cur
	itop int // iv.top
	icur int // iv.cur
}

var (
	cv      *DasView   // current viewer
	sl      *DasStatus // status line
	history []*DasHist
)

func funcMsg(arg interface{}) string {
	df := arg.(*DasFunc)
	if df.sect {
		fold_sign := "-"
		if df.fold {
			fold_sign = "+"
		}
		return fmt.Sprintf("%s section: %s", fold_sign, df.name)
	} else {
		return fmt.Sprintf("   %x: %s", df.start, df.name)
	}
}

func insnMsg(arg interface{}) string {
	var ls string

	dl := arg.(*DasLine)

	arw := "   "
	if cv.arrow {
		jmp := cv.line[cv.cur].(*DasLine)

		target, _ := scv.ParseInt(jmp.args, 0, 64)
		target += cv.off

		if dl.offset == jmp.offset {
			arw = "+--"
		} else if dl.offset == target {
			arw = "+->"
		} else if jmp.offset < dl.offset && dl.offset < target {
			arw = "|  "
		} else if target < dl.offset && dl.offset < jmp.offset {
			arw = "|  "
		}
	}

	if cv.raw {
		ls = fmt.Sprintf(" %s %4x:  %-*s   %s",
			arw, dl.offset, cv.mow, dl.opcode, dl.rawline)
	} else {
		ls = fmt.Sprintf(" %s %4x:  %-*s   %s",
			arw, dl.offset-cv.off, cv.miw, dl.mnemonic, dl.args)

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
		return fmt.Sprintf("section: %s (%d functions)", df.name, df.start)
	} else {
		return fmt.Sprintf("function: %s", df.name)
	}
}

func insnStat(arg interface{}) string {
	dl := arg.(*DasLine)
	desc := LookupInsn(dl.mnemonic)

	if len(desc) > 0 {
		return fmt.Sprintf("%s: %s (%s)", "instruction", dl.mnemonic, desc)
	} else {
		return "instruction: " + dl.mnemonic
	}
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
		cs = tui.DefaultTxBuilder.Build(" ", fg, bg)
		for x < dv.Width-2 {
			for _, vv := range cs {
				w := vv.Width()
				buf.Set(x+1, y+1, vv)
				x += w
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

func update(dv *DasView) {
	// update max insn/opcode width
	dv.miw = 0
	dv.mow = 0

	for _, ln := range dv.line {
		insn := ln.(*DasLine)
		if len(insn.opcode) > dv.mow {
			dv.mow = len(insn.opcode)
		}
		if len(insn.mnemonic) > dv.miw {
			dv.miw = len(insn.mnemonic)
		}
	}
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

func home(dv *DasView) {
	dv.top = 0
	dv.cur = 0
}

func end(dv *DasView) {
	dv.cur = len(dv.line) - 1
	dv.top = dv.cur - dv.Height + 3

	if dv.top < 0 {
		dv.top = 0
	}
}

func toggle(f *DasFunc) {
	// toggle folding state
	f.fold = !f.fold

	// count entries again
	c := 0
	for _, f2 := range funcs {
		if f2.sect {
			if !f2.fold {
				c += int(f2.start)
			}
			c++
		}
	}

	// rebuild function list
	line := make([]interface{}, c)

	i := 0
	skip := false

	for _, f2 := range funcs {
		// section is always added
		if f2.sect {
			line[i] = f2
			i++
			skip = f2.fold
		} else if !skip {
			line[i] = f2
			i++
		}
	}

	cv.line = line
}

// return index of the given function
func find(dv *DasView, name string) (*DasFunc, int, int) {
	skip := false
	sect := 0
	hide := 0 // hidden functions due to foding
	tmp := 0  // functions in the current section

	for i, f := range funcs {
		if f.sect {
			// keep hidden
			hide += tmp
			sect = i
			skip = f.fold

			if skip {
				tmp = int(f.start)
			} else {
				tmp = 0
			}
			continue
		}

		if f.name != name {
			continue
		}

		// update function index
		if skip {
			// if it's skipped, use section index instead
			i = sect
		}

		// count alread skipped sections
		i -= hide

		t := i
		if i+dv.Height-2 >= len(dv.line) {
			t = len(dv.line) - dv.Height + 3

			if t < 0 {
				t = 0
			}
		}
		return f, t, i
	}
	return nil, -1, -1
}

// push current function to the history
func push(fun *DasFunc, top, cur int, fv, iv *DasView) {
	history = append(history, &DasHist{fun, top, cur, 0, 0})

	fv.top = top
	fv.cur = cur

	iv.top = 0
	iv.cur = 0
	iv.off = fun.start
	iv.BorderLabel = fun.name

	iv.line = make([]interface{}, len(fun.insn))
	for i, l := range fun.insn {
		iv.line[i] = l
	}

	update(iv)
	cv = iv
}

// pop function from the history
func pop(fv, iv *DasView) {
	history = history[:len(history)-1]

	if len(history) == 0 {
		// switch to function view
		cv = fv
		resize(fv)
		return
	}

	h := history[len(history)-1]

	fv.top = h.ftop
	fv.cur = h.fcur

	iv.top = h.itop
	iv.cur = h.icur
	iv.off = h.fun.start
	iv.BorderLabel = h.fun.name

	iv.line = make([]interface{}, len(h.fun.insn))
	for i, l := range h.fun.insn {
		iv.line[i] = l
	}

	update(iv)
}

func enter(fv, iv *DasView) {
	if cv.insn {
		// move to a different function if it's call or return
		ln := iv.line[iv.cur].(*DasLine)

		if ln.optype == OPTYPE_OTHER {
			return
		}

		if ln.optype == OPTYPE_RETURN {
			pop(fv, iv)
			return
		}

		// for OPTYPE_BRANCH
		if ln.local {
			for {
				if ln.target > ln.offset {
					down(cv)
				} else {
					up(cv)
				}

				t := iv.line[iv.cur].(*DasLine)
				if t.offset == ln.target {
					break
				}
			}
			return
		}

		// function call
		fun, top, idx := find(fv, ln.args)
		if fun != nil {
			h := history[len(history)-1]
			// save current index
			h.itop = iv.top
			h.icur = iv.cur

			push(fun, top, idx, fv, iv)
		}
		return
	}

	f := fv.line[fv.cur].(*DasFunc)
	if f.sect {
		toggle(f)
	} else {
		// switch to instruction view
		push(f, fv.top, fv.cur, fv, iv)
		resize(iv)
	}
}

func escape(fv, iv *DasView) {
	if len(history) > 0 {
		pop(fv, iv)
	}
}

func list(dv *DasView) {
	if len(history) == 0 {
		return
	}

	h := history[len(history)-1]
	history = nil

	// switch to function view
	dv.top = h.ftop
	dv.cur = h.fcur

	cv = dv
}

func rawMode(dv *DasView) {
	if dv.insn {
		// toggle to show raw opcode
		dv.raw = !dv.raw
	}
}

func arrowMode(dv *DasView) {
	dv.arrow = false
	if !dv.insn {
		return
	}

	dl := dv.line[dv.cur].(*DasLine)
	if str.HasPrefix(dl.mnemonic, "j") && str.HasPrefix(dl.args, "0x") {
		dv.arrow = true
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
	arrowMode(dv)
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
		insn:      true,
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

	tui.Handle("/sys/kbd/<home>", func(e tui.Event) {
		home(cv)
		render(cv)
	})

	tui.Handle("/sys/kbd/<end>", func(e tui.Event) {
		end(cv)
		render(cv)
	})

	tui.Handle("/sys/wnd/resize", func(tui.Event) {
		resize(cv)
		render(cv)
	})

	tui.Handle("/sys/kbd/<enter>", func(tui.Event) {
		enter(fv, iv)
		render(cv)
	})

	tui.Handle("/sys/kbd/<escape>", func(tui.Event) {
		escape(fv, iv)
		render(cv)
	})

	tui.Handle("/sys/kbd/v", func(tui.Event) {
		rawMode(cv)
		render(cv)
	})

	tui.Handle("/sys/kbd/l", func(tui.Event) {
		list(fv)
		render(fv)
	})

	tui.Loop()
}
