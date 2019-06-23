/*
 * DAS - DisASsembler (not for MB)
 *
 * Copyright (C) 2017-2019  Namhyung Kim <namhyung@gmail.com>
 *
 * Released under MIT license.
 */
package main

import (
	"fmt"
	tui "github.com/gizak/termui"
	"image"
	scv "strconv"
	str "strings"
)

const (
	// text styles
	normal = iota
	focus
	special
)

type DasView struct {
	tui.Block // embedded

	Height int
	Width  int

	styles [3]tui.Style

	top   int
	cur   int
	off   int64
	insn  bool
	raw   bool
	arrow bool
	miw   int // max insn width
	mow   int // max opcode width
	line  []interface{}
	msg   func(*DasParser, interface{}) string
	stat  func(*DasParser, interface{}) string
	dp    *DasParser
}

type DasStatus struct {
	tui.Block // embedded

	Height int
	Width  int

	style tui.Style
	line  string
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
	search  bool
	sname   string // name to search
	smove   bool   // move by search
)

func funcMsg(p *DasParser, arg interface{}) string {
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

func insnMsg(p *DasParser, arg interface{}) string {
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
			ls += lookupStrings(dl.comment, true)
		}
	}

	return ls
}

func funcStat(p *DasParser, arg interface{}) string {
	if search {
		return "search: " + sname
	}

	s := ""
	df := arg.(*DasFunc)
	if df.sect {
		s = fmt.Sprintf("section: %s (%d functions)", df.name, df.start)
	} else {
		s = fmt.Sprintf("function: %s", df.name)
	}

	if smove && len(sname) > 0 {
		s += fmt.Sprintf("  (search: %s)", sname)
	}
	smove = false
	return s
}

func insnStat(p *DasParser, arg interface{}) string {
	return describeInsn(p, arg.(*DasLine))
}

func (dv *DasView) Draw(buf *tui.Buffer) {
	// erase entire buffer
	buf.Fill(tui.NewCell(' ', dv.styles[normal]), dv.GetRect())

	// draw borders
	dv.Block.Draw(buf)

	y := 0

	for i, dl := range dv.line {
		if i < dv.top {
			continue
		}

		var st tui.Style

		if i == dv.cur {
			st = dv.styles[focus]
		} else {
			st = dv.styles[normal]

			if dv.insn {
				insn := dl.(*DasLine)

				if insn.optype == OPTYPE_BRANCH ||
					insn.optype == OPTYPE_RETURN {
					st = dv.styles[special]
				}
			} else {
				fun := dl.(*DasFunc)

				if fun.sect {
					st = dv.styles[special]
				}
			}
		}

		ls := dv.msg(dv.dp, dl)
		buf.SetString(ls, st, image.Pt(1, y+1))
		buf.Fill(tui.NewCell(' ', st), image.Rect(len(ls)+1, y+1, dv.Dx()-1, y+2))

		y++

		if y == dv.Max.Y-2 {
			break
		}
	}

	sl.line = dv.stat(dv.dp, dv.line[dv.cur])
}

func (ds *DasStatus) Draw(buf *tui.Buffer) {
	buf.Fill(tui.NewCell(' ', ds.style), ds.GetRect())
	buf.SetString(ds.line, ds.style, ds.Min)
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
	if search {
		return
	}

	if dv.cur == 0 {
		return
	}

	dv.cur--

	if dv.cur < dv.top {
		dv.top = dv.cur
	}
}

func down(dv *DasView) {
	if search {
		return
	}

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
	if search {
		return
	}

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
	if search {
		return
	}

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
	if search {
		return
	}

	dv.top = 0
	dv.cur = 0
}

func end(dv *DasView) {
	if search {
		return
	}

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

		// 'full' requires an exact match
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

func doSearch(dv *DasView) {
	orig := dv.cur
	dv.cur = -1

	nextSearch(dv)

	// restore original index if not found
	if dv.cur == -1 {
		dv.cur = orig
	}
}

func prevSearch(dv *DasView) {
	if search {
		addSearch("p")
		return
	}

	if len(sname) == 0 {
		return
	}

	for i := dv.cur - 1; i >= 0; i-- {
		fun := dv.line[i].(*DasFunc)

		if !str.Contains(fun.name, sname) {
			continue
		}
		dv.cur = i
		dv.top = i
		break
	}
	smove = true
}

func nextSearch(dv *DasView) {
	if search {
		addSearch("n")
		return
	}

	if len(sname) == 0 {
		return
	}

	for i := dv.cur + 1; i < len(dv.line); i++ {
		fun := dv.line[i].(*DasFunc)

		if !str.Contains(fun.name, sname) {
			continue
		}
		dv.cur = i

		t := i
		if i+dv.Height-2 >= len(dv.line) {
			t = len(dv.line) - dv.Height + 3

			if t < 0 {
				t = 0
			}
		}
		dv.top = t
		break
	}
	smove = true
}

// push current function to the history
func push(fun *DasFunc, top, cur int, fv, iv *DasView) {
	history = append(history, &DasHist{fun, top, cur, 0, 0})

	fv.top = top
	fv.cur = cur

	iv.top = 0
	iv.cur = 0
	iv.off = fun.start
	iv.Title = fun.name

	if fun.insn == nil {
		parseCapstoneFunc(iv.dp, fun)
	}

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
	iv.Title = h.fun.name

	iv.line = make([]interface{}, len(h.fun.insn))
	for i, l := range h.fun.insn {
		iv.line[i] = l
	}

	update(iv)
}

func enter(fv, iv *DasView) {
	if search {
		search = false
		doSearch(fv)
		return
	}

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
	if search {
		// cancel search
		search = false
		sname = ""
		return
	}

	if len(history) > 0 {
		pop(fv, iv)
	}
}

func backspace(dv *DasView) {
	// delete search name
	if search && len(sname) > 0 {
		sname = sname[:len(sname)-1]
	}
}

func list(dv *DasView) {
	if search {
		addSearch("l")
		return
	}

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

func addSearch(key string) {
	switch key {
	case "<Backspace>":
	case "<C-<Backspace>>":
		backspace(cv)

	case "<space>":
		sname += " "
	case "<tab>":
	case "<left>":
	case "<right>":
		break
	default:
		sname += key
	}
}

func rawMode(dv *DasView) {
	if search {
		addSearch("v")
		return
	}

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
	if dl.optype == OPTYPE_BRANCH && dl.local {
		dv.arrow = true
	}
}

func resize(dv *DasView) {
	w, h := tui.TerminalDimensions()

	dv.Width = w - 1
	dv.Height = h - 1
	dv.SetRect(0, 0, w, h-1)

	sl.Width = w
	sl.Height = 1
	sl.SetRect(0, h-1, w, h)
}

func render(dv *DasView) {
	arrowMode(dv)
	tui.Render(dv) // it will update the status line (sl)
	tui.Render(sl)
}

func ShowTUI(p *DasParser) {
	if err := tui.Init(); err != nil {
		panic(err)
	}
	defer tui.Close()

	text_styles := [3]tui.Style{tui.NewStyle(tui.ColorWhite, tui.ColorBlack),
		tui.NewStyle(tui.ColorWhite, tui.ColorBlue, tui.ModifierBold),
		tui.NewStyle(tui.ColorYellow, tui.ColorBlack)}
	title_style := tui.NewStyle(tui.ColorGreen, tui.ColorBlack)
	status_style := tui.NewStyle(tui.ColorBlack, tui.ColorWhite)

	// function viewer
	fv := &DasView{
		Block:  *tui.NewBlock(),
		styles: text_styles,
		msg:    funcMsg,
		stat:   funcStat,
		dp:     p,
	}

	fv.Title = "DAS: " + p.name
	fv.TitleStyle = title_style

	fv.line = make([]interface{}, len(funcs))
	for i, f := range funcs {
		fv.line[i] = f
	}

	// insn viewer
	iv := &DasView{
		Block:  *tui.NewBlock(),
		styles: text_styles,
		insn:   true,
		msg:    insnMsg,
		stat:   insnStat,
		dp:     p,
	}
	iv.TitleStyle = title_style

	// status line
	sl = &DasStatus{
		Block: *tui.NewBlock(),
		style: status_style,
	}

	cv = fv
	resize(cv)
	render(cv)

	evt := tui.PollEvents()
	done := false

	// handle key pressing
	for !done {
		e := <-evt

		switch e.ID {
		case "q":
			if search {
				addSearch("q")
				render(cv)
				continue
			}
			fallthrough
		case "<C-c>":
			done = true
		case "<Up>", "k":
			up(cv)
		case "<Down>", "j":
			down(cv)
		case "<Previous>":
			pageUp(cv)
		case "<Next>":
			pageDown(cv)
		case "<Home>":
			home(cv)
		case "<End>":
			end(cv)
		case "<Resize>":
			resize(cv)
		case "<Enter>":
			enter(fv, iv)
		case "<Escape>":
			escape(fv, iv)
		case "<Backspace>":
			backspace(cv)
		case "v":
			rawMode(cv)
		case "l":
			list(fv)
		case "n":
			nextSearch(fv)
		case "p":
			prevSearch(fv)
		default:
			if !search && cv == fv && e.ID == "/" {
				sname = "" // clear previous search
				search = true
			} else if search {
				addSearch(e.ID)
			}
		}
		render(cv)
	}
}
