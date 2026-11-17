package shell

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"
)

var (
	colorTransition = ui.ElementTransition{
		Colors:   true,
		Duration: 120 * time.Millisecond,
	}
	heightTransition = ui.ElementTransition{
		Height:    true,
		Animation: &ui.Snappy,
	}
	rowInsertTransition = ui.ElementTransition{
		Position:  true,
		Colors:    true,
		Animation: &ui.Snappy,
		Enter:     &ui.Motion{Collapse: true, Y: 6},
		Exit:      &ui.Motion{Collapse: true},
	}
)

var bitmapCache = struct {
	mu    sync.Mutex
	items map[string]*ui.Bitmap
}{
	items: map[string]*ui.Bitmap{},
}

func cachedBitmap(pngData []byte) *ui.Bitmap {
	if len(pngData) == 0 {
		return nil
	}
	sum := sha256.Sum256(pngData)
	key := hex.EncodeToString(sum[:12])
	bitmapCache.mu.Lock()
	if bm, ok := bitmapCache.items[key]; ok {
		bitmapCache.mu.Unlock()
		return bm
	}
	bitmapCache.mu.Unlock()

	bm, err := ui.DecodeBitmap(pngData)
	if err != nil {
		return nil
	}
	bitmapCache.mu.Lock()
	if len(bitmapCache.items) > 64 {
		bitmapCache.items = map[string]*ui.Bitmap{}
	}
	bitmapCache.items[key] = bm
	bitmapCache.mu.Unlock()
	return bm
}

func applyShellTheme(c *ui.Context, dark bool) {
	base := ui.LightTheme()
	if dark {
		base = ui.DarkTheme()
		base.Dark = true
		base.Background = ui.Hex("#111419")
		base.Surface = ui.Hex("#1A1F27")
		base.SurfaceHover = ui.Hex("#222833")
		base.SurfacePressed = ui.Hex("#2A3240")
		base.Border = ui.Hex("#2A313D")
		base.Selection = ui.Hex("#1C2F4D")
		base.Text = ui.Hex("#F3F4F6")
		base.TextMuted = ui.Hex("#94A3B8")
		base.Accent = ui.Hex("#2563EB")
		base.AccentHover = ui.Hex("#1D4ED8")
		base.AccentPressed = ui.Hex("#1E40AF")
		base.AccentText = ui.Hex("#FFFFFF")
		base.InactiveAccent = ui.Hex("#475569")
		base.Focus = ui.Hex("#64A8FF").Alpha(0.65)
		base.Inverse = ui.Hex("#F3F4F6")
		base.InverseText = ui.Hex("#111419")
		base.Scrollbar = ui.RGBA(255, 255, 255, 0.32)
	} else {
		base.Dark = false
		base.Background = ui.Hex("#F3F5F8")
		base.Surface = ui.Hex("#FFFFFF")
		base.SurfaceHover = ui.Hex("#F1F5F9")
		base.SurfacePressed = ui.Hex("#E2E8F0")
		base.Border = ui.Hex("#E2E8F0")
		base.Selection = ui.Hex("#E8F1FD")
		base.Text = ui.Hex("#0F172A")
		base.TextMuted = ui.Hex("#64748B")
		base.Accent = ui.Hex("#1769D2")
		base.AccentHover = ui.Hex("#1358B0")
		base.AccentPressed = ui.Hex("#0F468D")
		base.AccentText = ui.Hex("#FFFFFF")
		base.InactiveAccent = ui.Hex("#94A3B8")
		base.Focus = ui.Hex("#1769D2").Alpha(0.55)
		base.Inverse = ui.Hex("#0F172A")
		base.InverseText = ui.Hex("#FFFFFF")
		base.Scrollbar = ui.RGBA(15, 23, 42, 0.28)
	}
	c.SetTheme(base)
}

// accentInk returns the readable blue accent for text and icons over Background, Surface, or Selection.
func accentInk(t *ui.Theme) ui.Color {
	if t.Dark {
		return ui.Hex(accentDark)
	}
	return ui.Hex(accentLight)
}

func monoText(c *ui.Context, s string) ui.Element {
	return ui.Text(c, s).Font("monospace").FontFeatures("tnum")
}

func uiBtn(c *ui.Context, key, label string) ui.Element {
	return ui.Button(c.Key(key), label).Cursor(ui.CursorPointer)
}

func uiPrimaryBtn(c *ui.Context, key, label string) ui.Element {
	return ui.PrimaryButton(c.Key(key), label).Cursor(ui.CursorPointer)
}

// surfaceCard styles a primary focus card using calibrated elevation (single border or subtle top bevel, no heavy ghost shadow).
func surfaceCard(c *ui.Context, key string) ui.Element {
	t := c.Theme()
	card := ui.Column(c.Key(key)).FillWidth().Radius(14).Background(t.Surface)
	if t.Dark {
		card.Border(1, t.Border).InsetShadow(0, 1, 0, 0, ui.RGBA(255, 255, 255, 0.06))
	} else {
		card.Shadow(0, 1, 4, 0, ui.RGBA(15, 23, 42, 0.05)).Border(1, t.Border.Alpha(0.85))
	}
	return card
}

// insetGroup creates an Inset Grouped container with rounded corners and internal dividers.
func insetGroup(c *ui.Context, key string, fn func()) {
	t := c.Theme()
	group := ui.Column(c.Key(key)).FillWidth().Radius(12).Background(t.Surface).Clip()
	if t.Dark {
		group.Border(1, t.Border).InsetShadow(0, 1, 0, 0, ui.RGBA(255, 255, 255, 0.05))
	} else {
		group.Border(1, t.Border)
	}
	group.Children(fn)
}

// groupRow renders an interactive list row inside an insetGroup with pointer cursor, smooth color transition, and chevron shift.
func groupRow(c *ui.Context, key, label string, onContent func(), trailing func()) ui.Element {
	t := c.Theme()
	row := ui.ButtonBase(c.Key(key)).FillWidth().Padding(12, 16).Label(label).
		Background(t.Surface).Cursor(ui.CursorPointer).Transition(colorTransition)
	if row.Pressed() {
		row.Background(t.SurfacePressed)
	} else if row.Hovered() {
		row.Background(t.SurfaceHover)
	}
	row.Children(func() {
		ui.Row(c).FillWidth().Gap(12).AlignItems(ui.Center).Children(func() {
			if onContent != nil {
				onContent()
			}
			if trailing != nil {
				trailing()
			} else {
				pose := ui.Pose{}
				if row.Hovered() {
					pose = ui.Pose{X: 2}
				}
				ui.Icon(c, phCaretRight).Width(15).Height(15).TextColor(t.TextMuted).AnimatePose(pose, ui.Snappy)
			}
		})
	})
	return row
}

// primaryActionButton renders the hero Oklab gradient action button with pointer cursor, subtle tactile bevel, and press spring.
func primaryActionButton(c *ui.Context, key, label string, icon *ui.SVG) ui.Element {
	t := c.Theme()
	from := ui.Hex("#1F73DC")
	to := ui.Hex("#1769D2")
	if t.Dark {
		from = ui.Hex("#2563EB")
		to = ui.Hex("#1D4ED8")
	}
	btn := ui.ButtonBase(c.Key(key)).FillWidth().Height(46).Radius(12).Label(label).
		Cursor(ui.CursorPointer).
		LinearGradient(ui.LinearGradient{
			From:  from,
			To:    to,
			Angle: 90,
			Oklab: true,
		}).
		InsetShadow(0, 1, 0, 0, ui.RGBA(255, 255, 255, 0.22)).
		Center()
	pose := ui.Pose{}
	if btn.Pressed() {
		pose = ui.Pose{Scale: 0.988}
	}
	btn.AnimatePose(pose, ui.Snappy)
	btn.Children(func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			if icon != nil {
				ui.Icon(c, icon).Width(17).Height(17).TextColor(ui.Hex("#FFFFFF"))
			}
			ui.Text(c, label).Bold().FontSize(14).TextColor(ui.Hex("#FFFFFF")).SingleLine()
		})
	})
	return btn
}

// appIconBadge renders the extracted AppIcon PNG if available, otherwise falls back to a crisp Phosphor badge.
func appIconBadge(c *ui.Context, file archiveState, size float32) {
	if bm := cachedBitmap(file.report.IconPNG); bm != nil {
		ui.Image(c, bm).Size(size, size).Radius(size * 0.22).Fit(ui.Cover).
			Border(1, ui.RGBA(0, 0, 0, 0.08))
		return
	}
	glyph := phCubeFill
	bg := ui.Hex("#1769D2")
	if file.err != "" {
		glyph = phWarningFill
		bg = ui.Hex("#DC2626")
	} else if hasBlockedFairPlay(file.report) {
		glyph = phLockKeyDuotone
		bg = ui.Hex("#D97706")
	} else if bytes.Contains(bytes.ToLower([]byte(file.path)), []byte("stream")) {
		glyph = phPaperPlaneTiltDuotone
		bg = ui.Hex("#0284C7")
	}
	ui.Row(c).Width(size).Height(size).Radius(size * 0.24).Background(bg).
		InsetShadow(0, 1, 0, 0, ui.RGBA(255, 255, 255, 0.2)).
		Center().Children(func() {
		if glyph == phLockKeyDuotone || glyph == phPaperPlaneTiltDuotone {
			ui.Image(c, glyph).Width(size * 0.56).Height(size * 0.56).TextColor(ui.Hex("#FFFFFF"))
		} else {
			ui.Icon(c, glyph).Width(size * 0.54).Height(size * 0.54).TextColor(ui.Hex("#FFFFFF"))
		}
	})
}

func ambientGlow(c *ui.Context, dark bool) {
	glowCol := ui.Hex("#3B82F6").Alpha(0.11)
	edgeCol := ui.Hex("#3B82F6").Alpha(0)
	if dark {
		glowCol = ui.Hex("#60A5FA").Alpha(0.10)
		edgeCol = ui.Hex("#111419").Alpha(0)
	}
	ui.Box(c).Absolute().Top(-40).Right(-40).Width(360).Height(240).PassThrough().
		RadialGradient(ui.RadialGradient{
			Center: ui.Point{X: 0.8, Y: 0.15},
			Radius: 240,
			Oklab:  true,
			Stops: []ui.GradientStop{
				{Color: glowCol, At: 0},
				{Color: edgeCol, At: 1},
			},
		})
}

func stepIndicatorBar(c *ui.Context, active int, steps []string, onSelect func(int)) {
	t := c.Theme()
	ui.Row(c).FillWidth().Gap(6).AlignItems(ui.Center).Children(func() {
		for i, label := range steps {
			stepNum := i + 1
			isActive := stepNum == active
			isDone := stepNum < active
			bg := t.Surface
			fg := t.TextMuted
			border := t.Border
			if isActive {
				bg = t.Accent
				fg = t.AccentText
				border = t.Accent
			} else if isDone {
				bg = t.Selection
				fg = accentInk(t)
				border = accentInk(t).Alpha(0.35)
			}
			pill := ui.ButtonBase(c.Key(label)).Padding(5, 11).Radius(8).
				Background(bg).Border(1, border).Label(label).Transition(colorTransition)
			if onSelect != nil {
				pill.Cursor(ui.CursorPointer)
			}
			pill.Children(func() {
				ui.Text(c, label).FontSize(12).Bold().TextColor(fg).SingleLine()
			})
			if onSelect != nil && pill.Clicked() {
				onSelect(stepNum)
			}
			if i < len(steps)-1 {
				ui.Box(c).Width(16).Height(1).Background(t.Border)
			}
		}
	})
}

func statusBadgeColors(t *ui.Theme, severity string, msgBlock, msgWarn string) (bg, fg ui.Color) {
	if severity == msgBlock {
		if t.Dark {
			return ui.Hex("#3B1F22"), ui.Hex("#FCA5A5")
		}
		return ui.Hex("#FEE2E2"), ui.Hex("#DC2626")
	}
	if severity == msgWarn {
		if t.Dark {
			return ui.Hex("#3A2E1B"), ui.Hex("#FCD34D")
		}
		return ui.Hex("#FEF3C7"), ui.Hex("#D97706")
	}
	return t.Selection, accentInk(t)
}
