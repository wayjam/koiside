package shell

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"

	"koiside/locales"
)

type (
	navIndicatorMatch struct{ scope string }
	heroAppIconMatch  struct{ path string }
	radioDotMatch     struct{ group string }
)

var (
	motionFeedbackAnim = ui.Animation{
		Duration: 140 * time.Millisecond,
		Ease:     ui.EaseOut,
		Oklab:    true,
	}
	motionStatusColorAnim = ui.Animation{
		Duration: 240 * time.Millisecond,
		Oklab:    true,
	}
	motionProgressAnim = ui.Animation{
		Duration:  180 * time.Millisecond,
		Ease:      ui.EaseOut,
		NonMotion: true,
	}

	colorTransition = ui.ElementTransition{
		Colors:    true,
		Animation: &motionFeedbackAnim,
	}
	dropZoneTransition = ui.ElementTransition{
		Colors:    true,
		Shadows:   true,
		Animation: &motionFeedbackAnim,
	}
	heightTransition = ui.ElementTransition{
		Height:    true,
		Animation: &ui.Snappy,
	}
	workspaceEnterTransition = ui.ElementTransition{
		Duration:     180 * time.Millisecond,
		Ease:         ui.EaseOut,
		ExitDuration: 110 * time.Millisecond,
		Enter:        &ui.Motion{Opacity: 0, Y: 4},
	}
	feedbackBannerTransition = ui.ElementTransition{
		Duration:     180 * time.Millisecond,
		Ease:         ui.EaseOut,
		ExitDuration: 110 * time.Millisecond,
		Enter:        &ui.Motion{Opacity: 0, Y: 4, Scale: 0.985},
		Exit:         &ui.Motion{Opacity: 0},
	}
	rowInsertTransition = ui.ElementTransition{
		Position:     true,
		Colors:       true,
		Animation:    &ui.Snappy,
		ExitDuration: 140 * time.Millisecond,
		Enter:        &ui.Motion{Collapse: true, Y: 6},
		Exit:         &ui.Motion{Collapse: true},
	}
	stepCheckEnterTransition = ui.ElementTransition{
		Duration: 140 * time.Millisecond,
		Ease:     ui.EaseOut,
		Enter:    &ui.Motion{Scale: 0.65, Opacity: 0},
	}

	errorShakeFrames = []ui.Keyframe{
		{At: 0, Value: 0},
		{At: 45 * time.Millisecond, Value: 4, Ease: ui.EaseOut},
		{At: 90 * time.Millisecond, Value: -4, Ease: ui.EaseInOut},
		{At: 135 * time.Millisecond, Value: 2, Ease: ui.EaseInOut},
		{At: 180 * time.Millisecond, Value: 0, Ease: ui.EaseOut},
	}
	connectPulseFrames = []ui.Keyframe{
		{At: 0, Value: 1},
		{At: 100 * time.Millisecond, Value: 1.36, Ease: ui.EaseOut},
		{At: 260 * time.Millisecond, Value: 1, Ease: ui.EaseInOut},
	}
	waitBreathFrames = []ui.Keyframe{
		{At: 0, Value: 0.52},
		{At: 1100 * time.Millisecond, Value: 1, Ease: ui.EaseInOut},
	}
)

func navIndicatorTransition(scope string) ui.ElementTransition {
	return ui.ElementTransition{
		Position:  true,
		Size:      true,
		Colors:    true,
		Animation: &ui.Snappy,
		Match:     navIndicatorMatch{scope: scope},
	}
}

func heroIconTransition(path string) ui.ElementTransition {
	return ui.ElementTransition{
		Position:  true,
		Size:      true,
		Animation: &ui.Snappy,
		Match:     heroAppIconMatch{path: path},
		Fly:       true,
	}
}

func radioDotTransition(group string) ui.ElementTransition {
	return ui.ElementTransition{
		Position:  true,
		Size:      true,
		Colors:    true,
		Animation: &ui.Snappy,
		Match:     radioDotMatch{group: group},
	}
}

// applyPressPose applies a tactile GPU press spring without causing layout shifts.
func applyPressPose(el ui.Element, pressedScale float32) ui.Element {
	pose := ui.Pose{}
	if el.Pressed() {
		pose = ui.Pose{Scale: pressedScale}
	}
	return el.AnimatePose(pose, ui.Snappy)
}

// applyErrorShakeTrigger plays a horizontal micro-shake each time trigger increments.
func applyErrorShakeTrigger(el ui.Element, key string, trigger uint64) ui.Element {
	if trigger == 0 {
		return el
	}
	dx := el.Keyframes(key, errorShakeFrames, ui.KeyframeOptions{Run: trigger})
	if dx != 0 {
		el.Translate(dx, 0)
	}
	return el
}

// applyErrorShake plays a one-shot micro-shake whenever invalid transitions from false to true.
func applyErrorShake(el ui.Element, key string, invalid bool) ui.Element {
	type shakeState struct {
		prevInvalid bool
		run         uint64
	}
	st := ui.Local(el, key+"-state", func() shakeState { return shakeState{} })
	if invalid && !st.prevInvalid {
		st.run++
	}
	st.prevInvalid = invalid
	return applyErrorShakeTrigger(el, key, st.run)
}

// smoothProgress wraps ui.Progress with 180ms eased interpolation for determinate values.
func smoothProgress(c *ui.Context, key string, value float64, label string) ui.Element {
	if value < 0 {
		return ui.Progress(c.Key(key), value).Label(label)
	}
	if value > 1 {
		value = 1
	}
	wrap := ui.Box(c.Key(key))
	smoothed := wrap.AnimateTo("progress-val", float32(value), motionProgressAnim)
	wrap.Children(func() {
		ui.Progress(c, float64(smoothed)).FillWidth().Label(label)
	})
	return wrap
}

// statusDot renders a connection indicator with Oklab color morphing, a connect confirmation pulse,
// and a restrained waiting breath when idle/disconnected.
func statusDot(c *ui.Context, key string, size float32, target ui.Color, connected, hasErr bool) ui.Element {
	dot := ui.Row(c.Key(key)).Width(size).Height(size).Radius(size / 2)
	dot.Background(dot.AnimateColor("dot-color", target, motionStatusColorAnim))

	type dotState struct {
		wasConnected bool
		pulseRun     uint64
	}
	st := ui.Local(dot, "dot-pulse-state", func() dotState {
		return dotState{wasConnected: connected}
	})
	if connected && !st.wasConnected {
		st.pulseRun++
	}
	st.wasConnected = connected

	if st.pulseRun > 0 {
		scale := dot.Keyframes("dot-pulse", connectPulseFrames, ui.KeyframeOptions{Run: st.pulseRun})
		if scale != 1 {
			dot.Scale(scale, scale)
		}
	}
	if !connected && !hasErr {
		op := dot.Keyframes("dot-breath", waitBreathFrames, ui.KeyframeOptions{
			Repeat:    ui.RepeatForever,
			Alternate: true,
			NonMotion: true,
		})
		dot.Opacity(op)
	}
	return dot
}

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
	btn := ui.Button(c.Key(key), label).Cursor(ui.CursorPointer).Transition(colorTransition)
	return applyPressPose(btn, 0.985)
}

func uiPrimaryBtn(c *ui.Context, key, label string) ui.Element {
	btn := ui.PrimaryButton(c.Key(key), label).Cursor(ui.CursorPointer).Transition(colorTransition)
	return applyPressPose(btn, 0.985)
}

// uiBtnWithTip creates a button with an optional hover tooltip when disabled or active.
func uiBtnWithTip(c *ui.Context, key, label string, disabled bool, tip string) ui.Element {
	if disabled {
		if tip != "" {
			wrap := ui.Row(c.Key(key + "-tip-wrap")).Tooltip(tip)
			var btn ui.Element
			wrap.Children(func() {
				btn = uiBtn(c, key, label).Disabled(true)
			})
			return btn
		}
		return uiBtn(c, key, label).Disabled(true)
	}
	btn := uiBtn(c, key, label)
	if tip != "" {
		btn.Tooltip(tip)
	}
	return btn
}

// uiPrimaryBtnWithTip creates a primary button with an optional hover tooltip when disabled or active.
func uiPrimaryBtnWithTip(c *ui.Context, key, label string, disabled bool, tip string) ui.Element {
	if disabled {
		if tip != "" {
			wrap := ui.Row(c.Key(key + "-tip-wrap")).Tooltip(tip)
			var btn ui.Element
			wrap.Children(func() {
				btn = uiPrimaryBtn(c, key, label).Disabled(true)
			})
			return btn
		}
		return uiPrimaryBtn(c, key, label).Disabled(true)
	}
	btn := uiPrimaryBtn(c, key, label)
	if tip != "" {
		btn.Tooltip(tip)
	}
	return btn
}

// deviceBtn creates a button that requires a connected device. When disconnected,
// it is disabled and displays a hover tooltip instructing the user to connect and trust iPhone via USB.
func (m *Model) deviceBtn(c *ui.Context, msg locales.Messages, key, label string, primary bool, extraDisabled bool) ui.Element {
	noDev := !m.hasConnectedDevice()
	disabled := noDev || extraDisabled
	tip := ""
	if noDev {
		tip = msg.ToolInstallNeedDevice()
	}
	if primary {
		return uiPrimaryBtnWithTip(c, key, label, disabled, tip)
	}
	return uiBtnWithTip(c, key, label, disabled, tip)
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
	applyPressPose(row, 0.992)
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
	appIconBadgeWithMatch(c, file, size, "")
}

// appIconBadgeHero renders the app icon as a shared-element Fly hero across screens.
func appIconBadgeHero(c *ui.Context, file archiveState, size float32) {
	appIconBadgeWithMatch(c, file, size, file.path)
}

func appIconBadgeWithMatch(c *ui.Context, file archiveState, size float32, matchPath string) {
	var el ui.Element
	if bm := cachedBitmap(file.report.IconPNG); bm != nil {
		ctx := c
		if matchPath != "" {
			ctx = c.Key("hero-icon-" + matchPath)
		}
		el = ui.Image(ctx, bm).Size(size, size).Radius(size*0.22).Fit(ui.Cover).
			Border(1, ui.RGBA(0, 0, 0, 0.08))
	} else {
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
		ctx := c
		if matchPath != "" {
			ctx = c.Key("hero-icon-" + matchPath)
		}
		el = ui.Row(ctx).Width(size).Height(size).Radius(size*0.24).Background(bg).
			InsetShadow(0, 1, 0, 0, ui.RGBA(255, 255, 255, 0.2)).
			Center().Children(func() {
			if glyph == phLockKeyDuotone || glyph == phPaperPlaneTiltDuotone {
				ui.Image(c, glyph).Width(size * 0.56).Height(size * 0.56).TextColor(ui.Hex("#FFFFFF"))
			} else {
				ui.Icon(c, glyph).Width(size * 0.54).Height(size * 0.54).TextColor(ui.Hex("#FFFFFF"))
			}
		})
	}
	if matchPath != "" {
		el.Transition(heroIconTransition(matchPath))
	}
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

// brandLogoBadge renders the KoiSide brand mark inside a crafted macOS app icon tile.
// The pure background, crisp border, and soft elevation ensure the vibrant koi colors
// stay sharp and harmonious across light, dark, and translucent vibrancy backgrounds.
func brandLogoBadge(c *ui.Context, size float32) ui.Element {
	t := c.Theme()
	radius := size * 0.25
	iconSize := size * 0.75
	bg := ui.Hex("#FFFFFF")
	border := t.Border.Alpha(0.75)
	shadowCol := ui.RGBA(15, 23, 42, 0.08)
	if t.Dark {
		bg = ui.Hex("#1E2530")
		border = ui.Hex("#2A3342")
		shadowCol = ui.RGBA(0, 0, 0, 0.40)
	}
	blur := size * 0.12
	yOffset := size * 0.05
	badge := ui.Row(c).
		Width(size).Height(size).
		Radius(radius).
		Background(bg).
		Border(1, border).
		Shadow(0, yOffset, blur, 0, shadowCol).
		Center()
	badge.Children(func() {
		ui.Image(c, brandLogo).Size(iconSize, iconSize).Fit(ui.Contain)
	})
	return badge
}

func sidebarLogoGlow(c *ui.Context, dark bool) {
	glowCol := ui.Hex("#3B82F6").Alpha(0.08)
	edgeCol := ui.Hex("#3B82F6").Alpha(0)
	if dark {
		glowCol = ui.Hex("#60A5FA").Alpha(0.07)
		edgeCol = ui.Hex("#111419").Alpha(0)
	}
	ui.Box(c.Key("sidebar-logo-glow")).Absolute().Top(-20).Left(-20).Width(240).Height(140).PassThrough().
		RadialGradient(ui.RadialGradient{
			Center: ui.Point{X: 0.25, Y: 0.3},
			Radius: 150,
			Oklab:  true,
			Stops: []ui.GradientStop{
				{Color: glowCol, At: 0},
				{Color: edgeCol, At: 1},
			},
		})
}

func stepIndicatorBar(c *ui.Context, active int, steps []string, onSelect func(int)) {
	t := c.Theme()
	ui.Row(c).FillWidth().Wrap().Gap(8).AlignItems(ui.Center).Children(func() {
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
				applyPressPose(pill, 0.975)
			}
			pill.Children(func() {
				ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
					if isDone {
						ui.Icon(c.Key("step-done-"+label), phCheckCircleFill).Width(13).Height(13).
							TextColor(fg).Transition(stepCheckEnterTransition)
					}
					ui.Text(c, label).FontSize(12).Bold().TextColor(fg).SingleLine()
				})
			})
			if onSelect != nil && pill.Clicked() {
				onSelect(stepNum)
			}
			if i < len(steps)-1 {
				lineCol := t.Border
				if isDone {
					lineCol = accentInk(t).Alpha(0.45)
				}
				line := ui.Box(c.Key(fmt.Sprintf("step-line-%d", i))).Width(16).Height(1)
				line.Background(line.AnimateColor("line-col", lineCol, motionStatusColorAnim))
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
