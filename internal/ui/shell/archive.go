package shell

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"koiside/internal/ipa"
	"koiside/locales"
)

var validBundleIDRe = regexp.MustCompile(`^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$`)

type archiveState struct {
	path      string
	sizeBytes int64
	report    ipa.Report
	diff      ipa.Diff
	err       string
	ready     bool
}

func (m *Model) archives() []archiveState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]archiveState, len(m.files))
	copy(out, m.files)
	return out
}

func (m *Model) selectedArchive() (archiveState, bool) {
	files := m.archives()
	if len(files) == 0 {
		return archiveState{}, false
	}
	if m.selected < 0 || m.selected >= len(files) {
		return files[0], true
	}
	return files[m.selected], true
}

func (m *Model) resetArchiveSessionLocked(file archiveState) {
	if file.report.DisplayName != "" {
		m.editName = file.report.DisplayName
	} else {
		m.editName = filepath.Base(file.path)
	}
	m.editBundleID = file.report.BundleID
	m.editLocalizedName = ""
	m.removePaths = map[string]bool{}
	m.showEncDetails = false
	m.exportMsg = ""
	m.exportErr = ""
	m.exportedPath = ""
	m.transferState = ""
	m.transferErr = ""
	m.transfer = ""
	m.transferring = false
	m.userConfirmed = false
	m.taskStage = 1
	m.prepareMode = "choice"
	m.sourceKind = "local"
}

func (m *Model) selectArchiveIndex(idx int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx < 0 || idx >= len(m.files) {
		return
	}
	m.selected = idx
	m.resetArchiveSessionLocked(m.files[idx])
}
func (m *Model) removeArchiveIndex(idx int) {
	m.mu.Lock()
	if idx < 0 || idx >= len(m.files) {
		m.mu.Unlock()
		return
	}
	m.files = append(m.files[:idx], m.files[idx+1:]...)
	if len(m.files) == 0 {
		m.selected = 0
	} else {
		if m.selected >= len(m.files) {
			m.selected = len(m.files) - 1
		}
		m.resetArchiveSessionLocked(m.files[m.selected])
	}
	m.mu.Unlock()
	if m.win != nil {
		m.win.Invalidate()
	}
}

func (m *Model) inspect(path string) {
	var sizeBytes int64
	if info, err := os.Stat(path); err == nil {
		sizeBytes = info.Size()
	}
	report, err := ipa.Inspect(path)
	state := archiveState{path: path, sizeBytes: sizeBytes, report: report, ready: err == nil}
	if err != nil {
		state.err = err.Error()
		m.addLog("inspect failed: " + filepath.Base(path))
	} else {
		state.diff = ipa.Preview(report, ipa.Change{})
		m.addLog("inspected: " + filepath.Base(path))
	}
	m.mu.Lock()
	m.files = append(m.files, state)
	m.selected = len(m.files) - 1
	m.resetArchiveSessionLocked(state)
	m.mu.Unlock()
	if m.win != nil {
		m.win.Invalidate()
	}
}

func (m *Model) inspectPathsAsync(paths []string) {
	if len(paths) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	if m.inspectCancel != nil {
		m.inspectCancel()
	}
	m.inspecting = true
	m.inspectName = filepath.Base(paths[0])
	m.inspectCancel = cancel
	m.section = "文件"
	m.lastTaskSection = "文件"
	m.taskStage = 1
	m.mu.Unlock()
	if m.win != nil {
		m.win.Invalidate()
	}
	go func() {
		defer cancel()
		for _, p := range paths {
			if ctx.Err() != nil {
				break
			}
			m.mu.Lock()
			m.inspectName = filepath.Base(p)
			m.mu.Unlock()
			if m.win != nil {
				mygo.RunOnMain(func() { m.win.Invalidate() })
			}
			var sizeBytes int64
			if info, err := os.Stat(p); err == nil {
				sizeBytes = info.Size()
			}
			report, err := ipa.Inspect(p)
			if ctx.Err() != nil {
				break
			}
			state := archiveState{path: p, sizeBytes: sizeBytes, report: report, ready: err == nil}
			if err != nil {
				state.err = err.Error()
			} else {
				state.diff = ipa.Preview(report, ipa.Change{})
			}
			m.mu.Lock()
			m.files = append(m.files, state)
			m.selected = len(m.files) - 1
			m.resetArchiveSessionLocked(state)
			m.mu.Unlock()
		}
		m.mu.Lock()
		m.inspecting = false
		m.inspectCancel = nil
		m.mu.Unlock()
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) cancelInspect() {
	msg := m.msg(nil)
	m.mu.Lock()
	cancel := m.inspectCancel
	m.inspecting = false
	m.inspectCancel = nil
	m.dialogNote = msg.LibraryCanceled()
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.addLog("inspect canceled")
	if m.win != nil {
		m.win.Invalidate()
	}
}

func (m *Model) currentChange() ipa.Change {
	m.mu.Lock()
	defer m.mu.Unlock()
	var remove []string
	for p, on := range m.removePaths {
		if on {
			remove = append(remove, p)
		}
	}
	return ipa.Change{
		DisplayName:   m.editName,
		BundleID:      m.editBundleID,
		LocalizedName: m.editLocalizedName,
		Remove:        remove,
	}
}

func (m *Model) effectiveBundleID(file archiveState) string {
	if (m.prepareMode == "edit" || m.section == "差异") && strings.TrimSpace(m.editBundleID) != "" {
		return strings.TrimSpace(m.editBundleID)
	}
	return file.report.BundleID
}

func (m *Model) effectiveArchivePath(file archiveState) string {
	m.mu.Lock()
	exp := m.exportedPath
	m.mu.Unlock()
	if exp != "" {
		return exp
	}
	return file.path
}

func (m *Model) ensurePreparedArchivePath(file archiveState) (string, error) {
	m.mu.Lock()
	exp := m.exportedPath
	editMode := m.prepareMode == "edit"
	m.mu.Unlock()
	if exp != "" {
		return exp, nil
	}
	if !editMode {
		return file.path, nil
	}
	change := m.currentChange()
	diff := ipa.Preview(file.report, change)
	if len(diff.Items) == 0 {
		return file.path, nil
	}
	prepDir := filepath.Join(localDataDir(), "prepared")
	if err := os.MkdirAll(prepDir, 0o755); err != nil {
		return "", err
	}
	base := filepath.Base(file.path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if stem == "" {
		stem = "app"
	}
	outPath := filepath.Join(prepDir, stem+"-koiside.ipa")
	record, err := ipa.Export(file.path, outPath, change)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.exportedPath = record.OutputPath
	m.exportMsg = m.msg(nil).DiffExportSuccess(record.OutputPath)
	m.mu.Unlock()
	return record.OutputPath, nil
}

func (m *Model) exportSelectedAsync(outputPath string) {
	file, ok := m.selectedArchive()
	if !ok || !file.ready {
		return
	}
	change := m.currentChange()
	m.mu.Lock()
	m.exporting = true
	m.exportMsg = ""
	m.exportErr = ""
	m.exportedPath = ""
	m.mu.Unlock()
	if m.win != nil {
		m.win.Invalidate()
	}
	go func() {
		record, err := ipa.Export(file.path, outputPath, change)
		msg := m.msg(nil)
		m.mu.Lock()
		m.exporting = false
		if err != nil {
			m.exportErr = err.Error()
		} else {
			m.exportMsg = msg.DiffExportSuccess(record.OutputPath)
			m.exportedPath = record.OutputPath
		}
		m.mu.Unlock()
		if err != nil {
			m.addLog("export failed: " + filepath.Base(outputPath))
		} else {
			m.addLog("exported IPA: " + filepath.Base(record.OutputPath))
		}
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) taskHeaderAndSteps(c *ui.Context, msg locales.Messages, stage int) {
	t := c.Theme()
	ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
		ui.Text(c, msg.NavTask()).FontSize(12).Bold().TextColor(t.TextMuted).Grow(1)
		if uiBtn(c, "task-need-help", msg.NeedHelp()).Clicked() {
			m.openHelp("")
		}
	})
	stepIndicatorBar(c, stage, []string{
		msg.TaskStage1(),
		msg.TaskStage2(),
		msg.TaskStage3(),
		msg.TaskStage4(),
		msg.TaskStage5(),
	}, func(n int) {
		switch n {
		case 1:
			m.goTaskSection("文件", 1)
		case 2:
			m.goTaskSection("文件", 2)
		case 3:
			if m.prepareMode == "edit" {
				m.goTaskSection("差异", 3)
			} else {
				m.goTaskSection("文件", 3)
			}
		case 4:
			m.goTaskSection("交接", 4)
		case 5:
			m.goTaskSection("维护", 5)
		}
	})
}

func (m *Model) filesView(c *ui.Context, msg locales.Messages, compact bool) {
	t := c.Theme()
	stage := m.taskStage
	if stage < 1 || stage > 5 {
		stage = 1
	}

	m.taskHeaderAndSteps(c, msg, stage)

	if m.inspecting {
		m.checkingCard(c, msg)
		return
	}

	files := m.archives()
	if len(files) == 0 {
		ui.Column(c).FillWidth().Gap(4).Children(func() {
			ui.Text(c, msg.LibraryTitle()).FontSize(26).Bold()
			ui.Text(c.Key("device"), m.deviceStatusText(msg)).FontSize(13).TextColor(t.TextMuted)
		})
		emptyCard := surfaceCard(c, "empty-ipa-card").Padding(32, 24).Gap(12).AlignItems(ui.Center)
		if emptyCard.FileDragOver() {
			emptyCard.Border(2, accentInk(t)).Background(t.Selection)
		}
		if dropped := emptyCard.DroppedFiles(); len(dropped) > 0 {
			m.dropped = append([]string(nil), dropped...)
			for _, f := range dropped {
				m.inspect(f)
			}
		}
		emptyCard.Children(func() {
			ui.Image(c, phPackageDuotone).Width(56).Height(56).TextColor(accentInk(t))
			ui.Text(c, msg.LibraryEmptyTitle()).FontSize(18).Bold()
			ui.Text(c, msg.LibraryEmptySubtitle()).TextColor(t.TextMuted).FontSize(13)
			ui.Row(c).Gap(10).Children(func() {
				if uiPrimaryBtn(c, "empty-import", msg.ImportIPA()).Clicked() {
					m.pickIPA()
				}
				if uiBtn(c, "open-by-path", msg.OpenPathBtn()).Clicked() {
					m.openPathErr = ""
					m.openPathModal = true
				}
			})
			ui.Text(c, msg.HomeImportDragHint()).FontSize(11).TextColor(t.TextMuted)
			ui.Text(c, msg.LibraryOfflineSupported()).FontSize(12).TextColor(t.TextMuted)
		})
		return
	}

	if stage == 2 {
		m.routeView(c, msg, compact)
		return
	}
	if stage == 3 {
		m.prepareChoiceView(c, msg, compact)
		return
	}

	// Stage 1: Check & Summary (single focused task, no duplicate handoff box)
	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.LibraryTitle()).FontSize(26).Bold()
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Text(c.Key("device"), m.deviceStatusText(msg)).FontSize(13).TextColor(t.TextMuted).Grow(1)
			ui.Text(c, msg.LibrarySubtitle()).FontSize(12).TextColor(t.TextMuted)
		})
	})
	if compact {
		if m.narrowDetail {
			ui.Column(c).FillWidth().Gap(14).Children(func() {
				m.archiveSummary(c, msg)
			})
		} else {
			ui.Column(c).FillWidth().Gap(10).Children(func() {
				m.archiveList(c, msg, true)
				if uiBtn(c, "files-import-more", msg.ImportIPA()).FillWidth().Clicked() {
					m.pickIPA()
				}
				if uiBtn(c, "open-by-path", msg.OpenPathBtn()).FillWidth().Clicked() {
					m.openPathErr = ""
					m.openPathModal = true
				}
			})
		}
		return
	}

	ui.Row(c).FillWidth().Gap(18).AlignItems(ui.Stretch).Children(func() {
		ui.Column(c).Width(248).Shrink(0).Gap(10).Children(func() {
			m.archiveList(c, msg, false)
			if uiBtn(c, "files-import-more", msg.ImportIPA()).FillWidth().Clicked() {
				m.pickIPA()
			}
			if uiBtn(c, "open-by-path", msg.OpenPathBtn()).FillWidth().Clicked() {
				m.openPathErr = ""
				m.openPathModal = true
			}
		})
		ui.Column(c).Grow(1).MinWidth(0).Gap(14).Children(func() {
			m.archiveSummary(c, msg)
		})
	})
}

func (m *Model) checkingCard(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	card := surfaceCard(c, "checking-ipa-card").Padding(28, 24).Gap(16).AlignItems(ui.Center)
	card.Children(func() {
		ui.Image(c, phMagnifyingGlassDuotone).Width(56).Height(56).TextColor(accentInk(t))
		ui.Text(c, msg.LibraryCheckingTitle()).FontSize(18).Bold()
		if m.inspectName != "" {
			monoText(c, m.inspectName).FontSize(13).Bold().TextColor(accentInk(t))
		}
		ui.Text(c, msg.LibraryCheckingSubtitle()).FontSize(12).TextColor(t.TextMuted)
		ui.Progress(c, -1).Width(280).Label(msg.LibraryCheckingTitle())
		if uiBtn(c, "cancel-inspect", msg.LibraryCancel()).Clicked() {
			m.cancelInspect()
		}
	})
}

func (m *Model) archiveList(c *ui.Context, msg locales.Messages, compact bool) {
	t := c.Theme()
	ui.Text(c, msg.NavLibrary()).Bold().FontSize(14).TextColor(t.TextMuted)
	files := m.archives()
	insetGroup(c, "archive-list-group", func() {
		for i, file := range files {
			i, file := i, file
			baseName := filepath.Base(file.path)
			name := file.report.DisplayName
			if name == "" {
				name = baseName
			}
			selected := i == m.selected
			cardBg := t.Surface
			if selected {
				cardBg = t.Selection
			}
			item := ui.ButtonBase(c.Key(fmt.Sprintf("archive-%d", i))).FillWidth().Padding(10, 12).
				Background(cardBg).Label(name).Cursor(ui.CursorPointer).Transition(rowInsertTransition)
			if !selected && item.Hovered() {
				item.Background(t.SurfaceHover)
			}
			item.Children(func() {
				ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
					appIconBadge(c, file, 34)
					ui.Column(c).Grow(1).Gap(2).Children(func() {
						ui.Text(c, name).Bold().FontSize(13)
						sub := msg.LibraryFileInfo(baseName, valueOrUnknown(msg, file.report.Version))
						if file.sizeBytes > 0 {
							sub = sub + " · " + formatBytes(file.sizeBytes)
						}
						monoText(c, sub).FontSize(11).TextColor(t.TextMuted)
					})
					if selected {
						ui.Icon(c, phCaretRight).Width(14).Height(14).TextColor(accentInk(t))
					}
				})
			})
			if item.Clicked() {
				m.selectArchiveIndex(i)
				if compact {
					m.narrowDetail = true
				}
			}
			if selected {
				ui.Row(c).FillWidth().Padding(0, 12, 8, 56).Justify(ui.End).Children(func() {
					if uiBtn(c, fmt.Sprintf("archive-rm-%d", i), msg.ArchiveRemoveBtn()).Clicked() {
						m.removeArchiveIndex(i)
					}
				})
			}
			if i < len(files)-1 {
				ui.Divider(c)
			}
		}
	})
}

func hasUncertainMachO(report ipa.Report) bool {
	for _, f := range report.Findings {
		if f.Code == "cryptid" || f.Code == "macho" {
			return true
		}
	}
	return false
}

func (m *Model) archiveSummary(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	file, ok := m.selectedArchive()
	if !ok {
		ui.Text(c, msg.NoRecentFiles()).TextColor(t.TextMuted)
		return
	}
	baseName := filepath.Base(file.path)
	if file.err != "" {
		ui.Column(c.Key("summary-err-card")).FillWidth().Padding(18, 20).Gap(10).
			Radius(14).Background(t.Surface).Border(1, ui.Hex("#EF4444")).Children(func() {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phXCircleFill).Width(22).Height(22).TextColor(ui.Hex("#EF4444"))
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, msg.CheckDamagedTitle()).FontSize(17).Bold()
					monoText(c, baseName).FontSize(12).TextColor(t.TextMuted)
				})
			})
			ui.Text(c, msg.CheckDamagedDesc()).FontSize(13)
			ui.Text(c, msg.LibraryInspectFailed(file.err)).FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, msg.LibraryInspectFailedHint()).FontSize(12).TextColor(t.TextMuted)
			if uiPrimaryBtn(c, "damaged-choose-another", msg.LibraryChooseAnother()).Clicked() {
				m.pickIPA()
			}
		})
		return
	}
	if !file.ready {
		ui.Text(c, msg.LibraryWaitingInspect())
		return
	}

	if hasBlockedFairPlay(file.report) {
		if file.report.HasSinf {
			ui.Column(c.Key("store-sinf-ipa-card")).FillWidth().Padding(20, 22).Gap(12).
				Radius(14).Background(t.Surface).Border(1, accentInk(t).Alpha(0.55)).Children(func() {
				ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
					appIconBadge(c, file, 44)
					ui.Column(c).Grow(1).Gap(2).Children(func() {
						ui.Text(c, valueOrUnknown(msg, file.report.DisplayName)).FontSize(17).Bold()
						monoText(c, fmt.Sprintf("%s · v%s", valueOrUnknown(msg, file.report.BundleID), valueOrUnknown(msg, file.report.Version))).FontSize(12).TextColor(t.TextMuted)
					})
				})
				ui.Row(c).FillWidth().Padding(10, 14).Gap(10).Radius(10).
					Background(t.Selection).Border(1, ui.Hex("#10B981").Alpha(0.5)).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, phCheckCircleFill).Width(18).Height(18).TextColor(ui.Hex("#10B981"))
					ui.Column(c).Grow(1).Gap(2).Children(func() {
						ui.Text(c, msg.StoreSinfReadyTitle()).Bold().FontSize(13)
						ui.Text(c, msg.StoreSinfReadyDesc()).FontSize(12).TextColor(t.TextMuted)
					})
				})
				m.mu.Lock()
				busy := m.directInstallOn
				pct := m.directPct
				stage := m.directStage
				dErr := m.directErr
				dMsg := m.directDoneMsg
				m.mu.Unlock()
				if busy {
					ui.Progress(c, float64(pct)/100.0).FillWidth().Label(stage)
					ui.Text(c, fmt.Sprintf("%d%% · %s", pct, stage)).FontSize(12).TextColor(accentInk(t))
				}
				if dErr != "" {
					ui.Text(c, friendlyError(msg, dErr)).FontSize(12).TextColor(ui.Hex("#EF4444"))
				}
				if dMsg != "" {
					ui.Text(c, dMsg).FontSize(12).TextColor(ui.Hex("#10B981"))
				}
				ui.Row(c).Gap(10).Children(func() {
					instBtn := uiPrimaryBtn(c, "store-sinf-usb-install", msg.StoreSinfDirectInstallBtn())
					if busy {
						instBtn.Disabled(true)
					}
					if instBtn.Clicked() {
						m.directInstallStoreIPA(file.path, file.report.BundleID)
					}
					if uiBtn(c, "choose-another-ipa", msg.LibraryChooseAnother()).Clicked() {
						m.pickIPA()
					}
					if uiBtn(c, "enc-view-details", msg.LibraryViewDetails()).Clicked() {
						m.showEncDetails = !m.showEncDetails
					}
				})
				if m.showEncDetails {
					m.advancedDetailsBox(c, msg, file)
				}
			})
			return
		}
		ui.Column(c.Key("encrypted-ipa-card")).FillWidth().Padding(24, 22).Gap(12).
			AlignItems(ui.Center).Radius(14).Background(t.Surface).Border(1, ui.Hex("#F59E0B")).Children(func() {
			ui.Image(c, phLockKeyDuotone).Width(56).Height(56).TextColor(ui.Hex("#F59E0B"))
			ui.Text(c, msg.LibraryEncryptedTitle()).FontSize(18).Bold()
			ui.Text(c, msg.LibraryEncryptedSubtitle()).FontSize(13).TextColor(t.TextMuted)
			ui.Row(c).Gap(10).Children(func() {
				if uiPrimaryBtn(c, "choose-another-ipa", msg.LibraryChooseAnother()).Clicked() {
					m.pickIPA()
				}
				if uiBtn(c, "enc-view-details", msg.LibraryViewDetails()).Clicked() {
					m.showEncDetails = !m.showEncDetails
				}
			})
			if m.showEncDetails {
				m.advancedDetailsBox(c, msg, file)
			}
		})
		return
	}

	name := file.report.DisplayName
	if name == "" {
		name = msg.LibraryUnknownName()
	}

	card := surfaceCard(c, "summary-card").Padding(18, 20).Gap(14)
	card.Children(func() {
		ui.Row(c).Gap(14).AlignItems(ui.Center).Children(func() {
			appIconBadge(c, file, 48)
			ui.Column(c).Grow(1).Gap(3).Children(func() {
				ui.Text(c, name).FontSize(18).Bold()
				monoText(c, msg.LibraryFileInfo(baseName, valueOrUnknown(msg, file.report.Version))).FontSize(12).TextColor(t.TextMuted)
			})
		})

		if hasUncertainMachO(file.report) {
			ui.Row(c).FillWidth().Padding(10, 14).Gap(10).Radius(10).
				Background(t.SurfaceHover).Border(1, ui.Hex("#F59E0B")).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phWarningFill).Width(18).Height(18).TextColor(ui.Hex("#F59E0B"))
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c.Key("summary-banner-title"), msg.CheckUncertainTitle()).Role(ui.RoleStatus).Bold().FontSize(13)
					ui.Text(c, msg.CheckUncertainDesc()).FontSize(12).TextColor(t.TextMuted)
				})
			})
		} else {
			ui.Row(c).FillWidth().Padding(10, 14).Gap(10).Radius(10).
				Background(t.Selection).Border(1, ui.Hex("#10B981").Alpha(0.55)).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phCheckCircleFill).Width(18).Height(18).TextColor(ui.Hex("#10B981"))
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c.Key("summary-banner-title"), msg.CheckReadyBannerTitle()).Role(ui.RoleStatus).Bold().FontSize(13)
					ui.Text(c, msg.CheckReadyBannerDesc()).FontSize(12).TextColor(t.TextMuted)
				})
			})
		}

		sourceIdx := 2
		switch m.sourceKind {
		case "github":
			sourceIdx = 0
		case "self":
			sourceIdx = 1
		}
		ui.Column(c).FillWidth().Gap(6).Children(func() {
			ui.Text(c, msg.CheckSourceLabel()).FontSize(12).Bold().TextColor(t.TextMuted)
			sourceLabels := []string{
				msg.CheckSourceGitHub(),
				msg.CheckSourceSelfBuilt(),
				msg.CheckSourceLocalUnknown(),
			}
			seg := ui.SegmentedBase(c.Key("source-kind-seg"), &sourceIdx, len(sourceLabels))
			seg.Track.FillWidth().Wrap().Gap(6).Label(msg.CheckSourceLabel()).Children(func() {
				for idx, lbl := range sourceLabels {
					selected := idx == sourceIdx
					s := seg.Segment(idx).Padding(5, 11).Radius(8).MaxWidthPercent(100).
						Cursor(ui.CursorPointer).Transition(colorTransition)
					if selected {
						s.Background(t.Selection).Border(1, accentInk(t).Alpha(0.55))
					} else {
						s.Background(t.Background).Border(1, t.Border)
						if s.Hovered() {
							s.Background(t.SurfaceHover)
						}
					}
					s.Children(func() {
						txt := ui.Text(c, lbl).FontSize(12)
						if selected {
							txt.Bold().TextColor(accentInk(t))
						}
					})
				}
			})
			if seg.Track.Changed() {
				kinds := []string{"github", "self", "local"}
				m.sourceKind = kinds[sourceIdx]
			}
			ui.Text(c, msg.CheckSourceNote()).FontSize(11).TextColor(t.TextMuted)
		})

		ui.Divider(c)

		ui.Column(c).FillWidth().Gap(9).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
				ui.Text(c, msg.LibraryBundleID()).FontSize(13).TextColor(t.TextMuted).Width(112)
				monoText(c.Key("summary-bundle-id"), valueOrUnknown(msg, file.report.BundleID)).FontSize(13).Bold()
			})
			ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
				ui.Text(c, msg.LibraryVersion()).FontSize(13).TextColor(t.TextMuted).Width(112)
				monoText(c.Key("summary-version"), valueOrUnknown(msg, file.report.Version)).FontSize(13)
			})
			if len(file.report.Components) > 0 && file.report.Components[0].MinimumOS != "" {
				ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
					ui.Text(c, msg.LibraryMinOS()).FontSize(13).TextColor(t.TextMuted).Width(112)
					monoText(c, "iOS "+file.report.Components[0].MinimumOS+"+").FontSize(13)
				})
			}
			ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
				ui.Text(c, msg.LibraryCheckStatus()).FontSize(13).TextColor(t.TextMuted).Width(112)
				badgeText := statusLabel(msg, file.report)
				badgeBg, badgeFg := statusBadgeColors(t, badgeText, msg.SeverityBlock(), msg.SeverityWarn())
				ui.Row(c).Padding(2, 8).Radius(6).Background(badgeBg).Children(func() {
					ui.Text(c.Key("summary-status-badge"), badgeText).Role(ui.RoleStatus).FontSize(12).Bold().TextColor(badgeFg)
				})
			})
			if len(file.report.MachOs) > 0 {
				ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
					ui.Text(c, msg.LibraryArch()).FontSize(13).TextColor(t.TextMuted).Width(112)
					monoText(c, file.report.MachOs[0].Arch).FontSize(13)
				})
			}
		})

		ui.Column(c.Key("advanced-wrap")).FillWidth().Transition(heightTransition).Children(func() {
			ui.Collapsible(c.Key("advanced-collapsible"), msg.LibraryAdvanced(), &m.showAdvanced, func() {
				m.advancedDetailsBox(c, msg, file)
			}).Cursor(ui.CursorPointer)
		})

		ui.Row(c).FillWidth().Gap(10).Justify(ui.End).Children(func() {
			if uiBtn(c, "preview", msg.LibraryPrepareBtn()).Clicked() {
				m.prepareMode = "edit"
				m.goTaskSection("差异", 3)
			}
			if uiPrimaryBtn(c, "choose-route-btn", msg.CheckChooseRouteBtn()).Clicked() {
				m.goTaskSection("文件", 2)
			}
		})
	})
}

func (m *Model) routeView(c *ui.Context, msg locales.Messages, compact bool) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.RouteTitle()).FontSize(26).Bold()
		ui.Text(c, msg.RouteSubtitle()).TextColor(t.TextMuted)
	})

	if m.appsQueried {
		if sideloaded := m.sideloadedApps(); len(sideloaded) > 0 {
			ui.Row(c).FillWidth().Padding(10, 14).Gap(10).Radius(10).
				Background(t.Selection).Border(1, accentInk(t).Alpha(0.35)).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phInfo).Width(18).Height(18).TextColor(accentInk(t))
				ui.Text(c, msg.RouteSlotNotice(len(sideloaded))).FontSize(12).Grow(1)
			})
		}
	}

	routeStatusBadge := func(id string) (text string, bg, fg ui.Color) {
		switch id {
		case "sidestore":
			if !m.appsQueried {
				return msg.RouteStatusUnknown(), t.Background, t.TextMuted
			}
			if m.sideStoreApp != nil {
				return msg.RouteStatusInstalled(valueOrUnknown(msg, m.sideStoreApp.Version)), t.Selection, ui.Hex("#10B981")
			}
			if m.sideStoreEmbedded {
				return msg.RouteStatusEmbeddedLC(), t.Selection, ui.Hex("#10B981")
			}
			if t.Dark {
				return msg.RouteStatusNotInstalled(), ui.Hex("#3A2E1B"), ui.Hex("#FCD34D")
			}
			return msg.RouteStatusNotInstalled(), ui.Hex("#FEF3C7"), ui.Hex("#D97706")
		case "livecontainer":
			if !m.appsQueried {
				return msg.RouteStatusUnknown(), t.Background, t.TextMuted
			}
			if m.lcApp != nil {
				return msg.RouteStatusInstalled(valueOrUnknown(msg, m.lcApp.Version)), t.Selection, ui.Hex("#10B981")
			}
			if t.Dark {
				return msg.RouteStatusNotInstalled(), ui.Hex("#3A2E1B"), ui.Hex("#FCD34D")
			}
			return msg.RouteStatusNotInstalled(), ui.Hex("#FEF3C7"), ui.Hex("#D97706")
		default:
			return msg.RouteStatusPhase2(), t.Background, t.TextMuted
		}
	}

	routeOption := func(id, title, desc string) {
		selected := m.installRoute == id
		bg := t.Surface
		if selected {
			bg = t.Selection
		}
		badgeText, badgeBg, badgeFg := routeStatusBadge(id)
		btn := ui.ButtonBase(c.Key("route-"+id)).FillWidth().Padding(14, 16).Background(bg).
			Label(title).Description(badgeText + " · " + desc).Checked(selected).Cursor(ui.CursorPointer).Transition(colorTransition)
		btn.Children(func() {
			ui.Row(c).FillWidth().Gap(12).AlignItems(ui.Center).Children(func() {
				dotBorder := t.Border
				if selected {
					dotBorder = accentInk(t)
				}
				ui.Row(c).Width(18).Height(18).Radius(9).Border(2, dotBorder).Center().Children(func() {
					if selected {
						ui.Row(c).Width(9).Height(9).Radius(5).Background(accentInk(t))
					}
				})
				ui.Column(c).Grow(1).Gap(4).Children(func() {
					ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Text(c, title).Bold().FontSize(14).Grow(1)
						ui.Row(c).Padding(2, 8).Radius(6).Background(badgeBg).Children(func() {
							ui.Text(c, badgeText).FontSize(11).Bold().TextColor(badgeFg).SingleLine()
						})
					})
					ui.Text(c, desc).FontSize(12).TextColor(t.TextMuted)
				})
			})
		})
		if btn.Clicked() {
			m.installRoute = id
		}
	}

	mainPane := func() {
		insetGroup(c, "route-options-group", func() {
			routeOption("sidestore", msg.RouteSideStoreTitle(), msg.RouteSideStoreDesc())
			ui.Divider(c)
			routeOption("livecontainer", msg.RouteContainerTitle(), msg.RouteContainerDesc())
			ui.Divider(c)
			routeOption("advanced", msg.RouteAdvancedTitle(), msg.RouteAdvancedDesc())
		})

		m.routePrecheckGroup(c, msg)

		if m.installRoute == "livecontainer" {
			if m.lcPlacement != "outside" {
				m.lcPlacement = "inside"
			}
			placementOption := func(id, title, desc string) {
				selected := m.lcPlacement == id
				bg := t.Surface
				if selected {
					bg = t.Selection
				}
				btn := ui.ButtonBase(c.Key("lc-place-"+id)).FillWidth().Padding(12, 16).Background(bg).
					Label(title).Description(desc).Checked(selected).Cursor(ui.CursorPointer).Transition(colorTransition)
				btn.Children(func() {
					ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
						dotBorder := t.Border
						if selected {
							dotBorder = accentInk(t)
						}
						ui.Row(c).Width(16).Height(16).Radius(8).Border(2, dotBorder).Center().Children(func() {
							if selected {
								ui.Row(c).Width(8).Height(8).Radius(4).Background(accentInk(t))
							}
						})
						ui.Column(c).Grow(1).Gap(2).Children(func() {
							ui.Text(c, title).Bold().FontSize(13)
							ui.Text(c, desc).FontSize(11).TextColor(t.TextMuted)
						})
					})
				})
				if btn.Clicked() {
					m.lcPlacement = id
				}
			}
			surfaceCard(c, "lc-placement-card").Padding(14, 16).Gap(8).Children(func() {
				ui.Text(c, msg.RouteLCPlacementTitle()).Bold().FontSize(14)
				insetGroup(c, "lc-placement-group", func() {
					placementOption("inside", msg.RouteLCPlacementInsideTitle(), msg.RouteLCPlacementInsideDesc())
					ui.Divider(c)
					placementOption("outside", msg.RouteLCPlacementOutsideTitle(), msg.RouteLCPlacementOutsideDesc())
				})
			})

			if m.appsQueried && m.lcApp == nil {
				ui.Row(c).FillWidth().Padding(12, 14).Gap(10).Radius(10).
					Background(t.SurfaceHover).Border(1, ui.Hex("#F59E0B")).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, phWarningFill).Width(18).Height(18).TextColor(ui.Hex("#F59E0B"))
					ui.Text(c, msg.RouteLiveContainerNotInstalledWarn()).FontSize(12).Grow(1)
					if uiBtn(c, "lc-install-help", msg.DeviceViewToolGuide()).Clicked() {
						m.openHelp("setup")
					}
				})
			}
		} else if m.installRoute == "advanced" {
			surfaceCard(c, "adv-eval-card").Padding(16, 18).Gap(8).Children(func() {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, phInfo).Width(18).Height(18).TextColor(accentInk(t))
					ui.Text(c, msg.RouteAdvancedTitle()).Bold().FontSize(14)
				})
				ui.Text(c, msg.RouteAdvancedPhaseNotice()).FontSize(12).TextColor(t.TextMuted)
			})
		}

		ui.Row(c).Gap(10).Children(func() {
			if uiBtn(c, "route-back-check", msg.NavBack()).Clicked() {
				m.goTaskSection("文件", 1)
			}
			if uiPrimaryBtn(c, "route-continue", msg.RouteContinueBtn()).Clicked() {
				m.goTaskSection("文件", 3)
			}
		})
	}

	sidePane := func() {
		if file, ok := m.selectedArchive(); ok {
			surfaceCard(c, "route-file-side").Padding(14, 16).Gap(8).Children(func() {
				ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
					appIconBadge(c, file, 34)
					ui.Column(c).Grow(1).Gap(2).Children(func() {
						ui.Text(c, valueOrUnknown(msg, file.report.DisplayName)).Bold().FontSize(13)
						monoText(c, valueOrUnknown(msg, file.report.BundleID)).FontSize(11).TextColor(t.TextMuted)
					})
				})
			})
		}
		surfaceCard(c, "route-help-side").Padding(14, 16).Gap(6).Children(func() {
			ui.Text(c, msg.ToolsSectionTitle()).Bold().FontSize(13)
			ui.Text(c, msg.GuideStep3Note()).FontSize(12).TextColor(t.TextMuted)
			if uiBtn(c, "route-open-tools", msg.HomeOpenHelp()).Clicked() {
				m.openHelp("setup")
			}
		})
	}

	winW, _ := c.Size()
	if compact || (winW > 0 && winW < mediumWidth) {
		ui.Column(c).FillWidth().Gap(14).Children(func() {
			mainPane()
			sidePane()
		})
		return
	}
	ui.Row(c).FillWidth().Gap(18).AlignItems(ui.Stretch).Children(func() {
		ui.Column(c).Grow(1).MinWidth(0).Gap(14).Children(mainPane)
		ui.Column(c).Width(240).Shrink(0).Gap(14).Children(sidePane)
	})
}

func (m *Model) routePrecheckGroup(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	signedIn := false
	accountEmail := ""
	teamKind := msg.AccountTeamFree()
	if m.services.Accounts != nil {
		devSess := m.services.Accounts.Developer()
		signedIn = devSess.SignedIn()
		accountEmail = devSess.Email()
		if team, ok := devSess.ActiveTeam(); ok && !team.IsFreePersonal() {
			teamKind = msg.AccountTeamPaid()
		}
	}

	insetGroup(c, "route-precheck-group", func() {
		ui.Row(c).FillWidth().Padding(12, 16).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Text(c, msg.RoutePrecheckTitle()).Bold().FontSize(14).Grow(1)
			if uiBtn(c, "route-precheck-refresh", msg.DeviceRefresh()).Clicked() {
				m.detectDevices()
			}
		})
		ui.Divider(c)

		// 1. Device + Developer Mode
		ui.Row(c).FillWidth().Padding(10, 16).Gap(10).AlignItems(ui.Center).Children(func() {
			if m.hasConnectedDevice() {
				ui.Icon(c, phCheckCircleFill).Width(16).Height(16).TextColor(ui.Hex("#10B981"))
				devName := msg.DeviceCardTitle()
				if m.deviceInfo.Name != "" {
					devName = m.deviceInfo.Name
				}
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c.Key("route-precheck-device"), msg.RoutePrecheckDeviceOK(devName)).Role(ui.RoleStatus).FontSize(12).Bold()
					if m.devModeKnown && !m.devModeEnabled {
						ui.Text(c.Key("route-precheck-devmode"), msg.DeviceDevModeOff()).FontSize(11).TextColor(ui.Hex("#F59E0B"))
					}
				})
				if m.devModeKnown && !m.devModeEnabled {
					if uiBtn(c, "route-enable-devmode", msg.DeviceDevModeEnableBtn()).Clicked() {
						m.triggerDeveloperMode()
					}
				}
			} else {
				ui.Icon(c, phInfo).Width(16).Height(16).TextColor(t.TextMuted)
				ui.Text(c.Key("route-precheck-device"), msg.RoutePrecheckDeviceMissing()).Role(ui.RoleStatus).FontSize(12).TextColor(t.TextMuted).Grow(1)
			}
		})
		ui.Divider(c)

		// 2. Apple Account status & login jump with floating return card
		ui.Row(c).FillWidth().Padding(10, 16).Gap(10).AlignItems(ui.Center).Children(func() {
			if signedIn {
				ui.Icon(c, phCheckCircleFill).Width(16).Height(16).TextColor(ui.Hex("#10B981"))
				ui.Text(c.Key("route-precheck-account"), msg.RoutePrecheckAccountOK(accountEmail, teamKind)).Role(ui.RoleStatus).FontSize(12).Grow(1)
			} else {
				ui.Icon(c, phWarningFill).Width(16).Height(16).TextColor(ui.Hex("#F59E0B"))
				ui.Text(c.Key("route-precheck-account"), msg.RoutePrecheckAccountMissing()).Role(ui.RoleStatus).FontSize(12).Grow(1)
				if uiBtn(c, "route-signin-apple", msg.RoutePrecheckSignInBtn()).Clicked() {
					m.navigateToAccountForLogin("task", "文件", 2)
				}
			}
		})
		// 3. Companion tools status (SideStore / LiveContainer / LocalDevVPN)
		if m.hasConnectedDevice() && m.appsQueried {
			needHost := (m.installRoute == "sidestore" && m.sideStoreApp == nil && m.lcApp == nil) ||
				(m.installRoute == "livecontainer" && m.lcApp == nil)
			ui.Divider(c)
			ui.Row(c).FillWidth().Padding(10, 16).Gap(10).AlignItems(ui.Center).Children(func() {
				if !needHost && m.vpnApp != nil {
					ui.Icon(c, phCheckCircleFill).Width(16).Height(16).TextColor(ui.Hex("#10B981"))
					ui.Text(c, msg.RoutePrecheckToolsReady()).FontSize(12).Grow(1)
				} else {
					ui.Icon(c, phWarningFill).Width(16).Height(16).TextColor(ui.Hex("#F59E0B"))
					ui.Column(c).Grow(1).Gap(2).Children(func() {
						if needHost {
							ui.Text(c, msg.RoutePrecheckToolsMissing()).FontSize(12)
						}
						if m.vpnApp == nil {
							ui.Text(c, msg.RoutePrecheckVPNMissing()).FontSize(11).TextColor(t.TextMuted)
						}
					})
					if needHost {
						if m.installRoute == "livecontainer" {
							if uiBtn(c, "route-install-lcss", msg.ToolInstallLCSSBtn()).Clicked() {
								m.confirmToolInstall("livecontainer-sidestore")
							}
						} else {
							if uiBtn(c, "route-install-ss", msg.ToolInstallSideStoreBtn()).Clicked() {
								m.confirmToolInstall("sidestore")
							}
						}
					}
					if m.vpnApp == nil {
						if uiBtn(c, "route-install-vpn", msg.ToolInstallLocalDevVPNBtn()).Clicked() {
							c.OpenURL("https://apps.apple.com/app/localdevvpn/id6755608044")
						}
					}
				}
			})
			m.toolInstallStatusRow(c, msg)
		}
	})
}

func (m *Model) prepareChoiceView(c *ui.Context, msg locales.Messages, compact bool) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.PrepareTitle()).FontSize(26).Bold()
		ui.Text(c, msg.PrepareSubtitle()).TextColor(t.TextMuted)
	})

	file, hasFile := m.selectedArchive()

	mainPane := func() {
		insetGroup(c, "prepare-choice-group", func() {
			ui.Row(c).FillWidth().Padding(16, 18).Gap(14).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phCheckCircleFill).Width(22).Height(22).TextColor(ui.Hex("#10B981"))
				ui.Column(c).Grow(1).Gap(3).Children(func() {
					ui.Text(c, msg.PrepareKeepAsIsTitle()).Bold().FontSize(15)
					ui.Text(c, msg.PrepareKeepAsIsDesc()).FontSize(12).TextColor(t.TextMuted)
				})
				if uiPrimaryBtn(c, "prepare-keep-btn", msg.PrepareKeepAsIsBtn()).Clicked() {
					m.prepareMode = "choice"
					m.goTaskSection("交接", 4)
				}
			})
			ui.Divider(c)
			ui.Row(c).FillWidth().Padding(16, 18).Gap(14).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phWrench).Width(22).Height(22).TextColor(accentInk(t))
				ui.Column(c).Grow(1).Gap(3).Children(func() {
					ui.Text(c, msg.PrepareEditTitle()).Bold().FontSize(15)
					ui.Text(c, msg.PrepareEditDesc()).FontSize(12).TextColor(t.TextMuted)
				})
				if uiBtn(c, "prepare-edit-btn", msg.PrepareEditBtn()).Clicked() {
					m.prepareMode = "edit"
					m.goTaskSection("差异", 3)
				}
			})
		})

		if hasFile {
			m.conflictBanner(c, msg, file.report.BundleID)
		}

		ui.Row(c).Gap(10).Children(func() {
			if uiBtn(c, "prepare-back-route", msg.NavBack()).Clicked() {
				m.goTaskSection("文件", 2)
			}
		})
	}

	sidePane := func() {
		if hasFile {
			surfaceCard(c, "prepare-orig-side").Padding(14, 16).Gap(8).Children(func() {
				ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
					appIconBadge(c, file, 36)
					ui.Column(c).Grow(1).Gap(2).Children(func() {
						ui.Text(c, valueOrUnknown(msg, file.report.DisplayName)).Bold().FontSize(14)
						monoText(c, valueOrUnknown(msg, file.report.BundleID)).FontSize(11).TextColor(t.TextMuted)
					})
				})
			})
		}
	}

	winW, _ := c.Size()
	if compact || (winW > 0 && winW < mediumWidth) {
		ui.Column(c).FillWidth().Gap(14).Children(func() {
			mainPane()
			sidePane()
		})
		return
	}
	ui.Row(c).FillWidth().Gap(18).AlignItems(ui.Stretch).Children(func() {
		ui.Column(c).Grow(1).MinWidth(0).Gap(14).Children(mainPane)
		ui.Column(c).Width(240).Shrink(0).Gap(14).Children(sidePane)
	})
}

func (m *Model) conflictBanner(c *ui.Context, msg locales.Messages, targetID string) {
	t := c.Theme()
	if !m.appsQueried {
		ui.Row(c).FillWidth().Padding(12, 14).Gap(10).Radius(10).
			Background(t.Surface).Border(1, t.Border).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, phInfo).Width(18).Height(18).TextColor(t.TextMuted)
			ui.Text(c, msg.PrepareConflictUnknown()).FontSize(12).TextColor(t.TextMuted).Grow(1)
			if uiBtn(c, "conflict-refresh-device", msg.DeviceRefresh()).Clicked() {
				m.detectDevices()
			}
		})
		return
	}
	if match, ok := m.findInstalledConflict(targetID); ok {
		ui.Row(c).FillWidth().Padding(12, 14).Gap(10).Radius(10).
			Background(t.SurfaceHover).Border(1, ui.Hex("#F59E0B")).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, phWarningFill).Width(18).Height(18).TextColor(ui.Hex("#F59E0B"))
			ui.Text(c, msg.PrepareConflictFound(valueOrUnknown(msg, match.Name), match.BundleID, valueOrUnknown(msg, match.Version))).FontSize(12).Grow(1)
		})
		return
	}
	if targetID != "" {
		ui.Row(c).FillWidth().Padding(12, 14).Gap(10).Radius(10).
			Background(t.Selection).Border(1, ui.Hex("#10B981").Alpha(0.5)).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, phCheckCircleFill).Width(18).Height(18).TextColor(ui.Hex("#10B981"))
			ui.Text(c, msg.PrepareConflictClear(targetID)).FontSize(12).Grow(1)
		})
	}
}

func (m *Model) componentSwitchList(c *ui.Context, msg locales.Messages, file archiveState) bool {
	t := c.Theme()
	hasExtra := false
	for _, comp := range file.report.Components {
		if comp.Kind != "app" && comp.Kind != "主应用" {
			hasExtra = true
			break
		}
	}
	if !hasExtra {
		return false
	}
	ui.Text(c, msg.LibraryComponentsList()).FontSize(12).Bold()
	for _, comp := range file.report.Components {
		comp := comp
		if comp.Kind == "app" || comp.Kind == "主应用" {
			continue
		}
		kind := componentKindLabel(msg, comp.Kind)
		checked := m.removePaths[comp.Path]
		label := msg.LibraryRemoveComponent(comp.Path, kind)
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Switch(c.Key("rm-"+comp.Path), &checked).Cursor(ui.CursorPointer).Label(label)
			monoText(c, label).FontSize(11).TextColor(t.Text).Grow(1)
		})
		m.removePaths[comp.Path] = checked
	}
	return true
}

func (m *Model) advancedDetailsBox(c *ui.Context, msg locales.Messages, file archiveState) {
	t := c.Theme()
	ui.Column(c).FillWidth().Padding(12, 14).Gap(8).Radius(10).Background(t.Background).Border(1, t.Border).Children(func() {
		if file.report.SHA256 != "" {
			shortHash := file.report.SHA256
			if len(shortHash) > 24 {
				shortHash = shortHash[:24] + "…"
			}
			monoText(c, msg.LibrarySHA256()+": "+shortHash).FontSize(11).TextColor(t.TextMuted)
		}
		ui.Text(c, msg.LibraryComponentCount(len(file.report.Components))).FontSize(12)
		ui.Text(c, msg.LibraryDylibCount(len(file.report.Dylibs))).FontSize(12)

		hasExtra := m.componentSwitchList(c, msg, file)
		for _, comp := range file.report.Components {
			if comp.Kind == "app" || comp.Kind == "主应用" {
				kind := componentKindLabel(msg, comp.Kind)
				monoText(c, fmt.Sprintf("• %s (%s) — %s", comp.Path, kind, valueOrUnknown(msg, comp.BundleID))).FontSize(11)
			}
			if len(comp.URLSchemes) > 0 {
				monoText(c, msg.LibraryURLSchemes(strings.Join(comp.URLSchemes, ", "))).FontSize(11).TextColor(t.TextMuted)
			}
		}
		if !hasExtra && len(file.report.Components) > 0 {
			ui.Text(c, msg.LibraryComponentsEmpty()).FontSize(11).TextColor(t.TextMuted)
		}
		if len(file.report.Findings) > 0 {
			ui.Divider(c)
			ui.Text(c, msg.LibraryFindingsTitle()).FontSize(12).Bold()
			for _, f := range file.report.Findings {
				ui.Text(c, fmt.Sprintf("• [%s] %s", severityLabel(msg, f.Severity), findingDetail(msg, f))).FontSize(11).TextColor(t.TextMuted)
			}
		}
	})
}

func (m *Model) diffView(c *ui.Context, msg locales.Messages, compact bool) {
	t := c.Theme()
	m.taskHeaderAndSteps(c, msg, 3)

	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.DiffTitle()).FontSize(26).Bold()
		ui.Text(c, msg.DiffSubtitle()).FontSize(13).TextColor(t.TextMuted)
	})
	file, ok := m.selectedArchive()
	if !ok || !file.ready {
		ui.Text(c, msg.DiffNoPreview()).TextColor(t.TextMuted)
		return
	}

	change := m.currentChange()
	diff := ipa.Preview(file.report, change)

	origName := file.report.DisplayName
	if origName == "" {
		origName = filepath.Base(file.path)
	}
	afterName := m.editName
	if afterName == "" {
		afterName = origName
	}
	origID := file.report.BundleID
	afterID := m.editBundleID
	if afterID == "" {
		afterID = origID
	}
	bundleValid := afterID == "" || validBundleIDRe.MatchString(strings.TrimSpace(afterID))

	leftPane := func() {
		surfaceCard(c, "diff-meta-card").Padding(16, 18).Gap(10).Children(func() {
			ui.Text(c, msg.PrepareIntentTitle()).Bold().FontSize(14)
			intentIdx := 1
			if m.editIntent == "update" {
				intentIdx = 0
			}
			intentSeg := ui.Segmented(c.Key("edit-intent-seg"), &intentIdx,
				msg.PrepareIntentUpdate(),
				msg.PrepareIntentCopy(),
			).FillEqually().Cursor(ui.CursorPointer).Label(msg.PrepareIntentTitle())
			if intentSeg.Changed() {
				if intentIdx == 0 {
					m.editIntent = "update"
					m.editBundleID = origID
				} else {
					m.editIntent = "copy"
					if m.editBundleID == origID && origID != "" {
						m.editBundleID = origID + ".copy"
					}
				}
			}
			if m.editIntent == "update" {
				ui.Text(c, msg.PrepareIntentUpdateHint()).FontSize(11).TextColor(t.TextMuted)
			} else {
				ui.Text(c, msg.PrepareIntentCopyHint()).FontSize(11).TextColor(t.TextMuted)
			}

			ui.Divider(c)

			ui.Text(c, msg.DiffMetadataTitle()).Bold().FontSize(15)
			ui.Text(c, msg.DiffDisplayName()).FontSize(12).TextColor(t.TextMuted)
			ui.TextInput(c.Key("edit-display-name"), &m.editName).Placeholder(msg.DiffDisplayNamePlaceholder()).FillWidth().Label(msg.DiffDisplayName())

			ui.Text(c, msg.DiffBundleID()).FontSize(12).TextColor(t.TextMuted)
			ui.TextInput(c.Key("edit-bundle-id"), &m.editBundleID).Placeholder(msg.DiffBundleIDPlaceholder()).FillWidth().Label(msg.DiffBundleID())
			if !bundleValid {
				ui.Text(c, msg.PrepareBundleIDInvalid()).FontSize(11).TextColor(ui.Hex("#EF4444"))
			}

			ui.Text(c, msg.DiffLocalizedName()).FontSize(12).TextColor(t.TextMuted)
			ui.TextInput(c.Key("edit-localized-name"), &m.editLocalizedName).Placeholder(msg.DiffLocalizedNamePlaceholder()).FillWidth().Label(msg.DiffLocalizedName())

			m.componentSwitchList(c, msg, file)
		})

		m.conflictBanner(c, msg, afterID)

		insetGroup(c, "diff-notices-group", func() {
			ui.Row(c).FillWidth().Padding(12, 14).Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phWarningFill).Width(18).Height(18).TextColor(ui.Hex("#F59E0B"))
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, msg.DiffResignTitle()).Bold().FontSize(13)
					ui.Text(c, msg.DiffResignDesc()).FontSize(11).TextColor(t.TextMuted)
				})
			})
			ui.Divider(c)
			ui.Row(c).FillWidth().Padding(12, 14).Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phInfo).Width(18).Height(18).TextColor(accentInk(t))
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, msg.DiffIDChangedTitle()).Bold().FontSize(13)
					ui.Text(c, msg.DiffIDChangedDesc()).FontSize(11).TextColor(t.TextMuted)
				})
			})
		})

		ui.Row(c).Gap(10).Children(func() {
			if uiBtn(c, "back-summary", msg.NavBack()).Clicked() {
				m.prepareMode = "choice"
				m.goTaskSection("文件", 3)
			}
			expBtn := uiPrimaryBtn(c, "export-btn", msg.DiffExportBtn())
			if !bundleValid {
				expBtn.Disabled(true)
			}
			if expBtn.Clicked() {
				m.SaveCopy()
			}
		})
		m.choiceNote(c, msg)
	}

	rightPane := func() {
		surfaceCard(c, "visual-diff-card").Padding(16, 18).Gap(14).Children(func() {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
				appIconBadge(c, file, 32)
				ui.Text(c, msg.DiffPreviewTitle()).Bold().FontSize(15)
			})
			ui.Row(c).FillWidth().Gap(12).AlignItems(ui.Stretch).Children(func() {
				ui.Column(c).Grow(1).MinWidth(0).Padding(12, 14).Gap(4).Radius(10).Background(t.Background).Border(1, t.Border).Children(func() {
					ui.Text(c, msg.DiffBefore()).FontSize(11).TextColor(t.TextMuted)
					ui.Text(c, origName).Bold().FontSize(14)
					monoText(c, origID).FontSize(11).TextColor(t.TextMuted)
				})
				ui.Row(c).AlignSelf(ui.Center).Shrink(0).Children(func() {
					ui.Icon(c, phArrowRight).Width(18).Height(18).TextColor(t.TextMuted)
				})
				ui.Column(c).Grow(1).MinWidth(0).Padding(12, 14).Gap(4).Radius(10).Background(t.Selection).Border(1, accentInk(t).Alpha(0.45)).Children(func() {
					ui.Text(c, msg.DiffAfter()).FontSize(11).TextColor(accentInk(t))
					ui.Text(c, afterName).Bold().FontSize(14)
					monoText(c, afterID).FontSize(11).TextColor(t.TextMuted)
				})
			})
		})

		surfaceCard(c, "diff-items-card").Padding(14, 16).Gap(8).Children(func() {
			ui.Text(c, msg.DiffItemsTitle()).Bold().FontSize(14)
			if len(diff.Items) == 0 {
				ui.Text(c, msg.DiffNoChanges()).FontSize(12).TextColor(t.TextMuted)
			}
			for _, item := range diff.Items {
				monoText(c, fmt.Sprintf("%s · %s: %s → %s", item.Path, diffFieldLabel(msg, item.Field), diffActionLabel(msg, item.Before), diffActionLabel(msg, item.After))).FontSize(11)
			}
			if len(diff.Findings) > 0 {
				ui.Divider(c)
				ui.Text(c, msg.DiffFindingsTitle()).Bold().FontSize(14)
				for _, finding := range diff.Findings {
					ui.Text(c, fmt.Sprintf("[%s] %s", severityLabel(msg, finding.Severity), findingDetail(msg, finding))).FontSize(12)
				}
			}
		})
	}

	winW, _ := c.Size()
	if compact || (winW > 0 && winW < mediumWidth) {
		ui.Column(c).FillWidth().Gap(14).Children(func() {
			leftPane()
			rightPane()
		})
		return
	}

	ui.Row(c).FillWidth().Gap(16).AlignItems(ui.Stretch).Children(func() {
		ui.Column(c).Width(316).Shrink(0).Gap(14).Children(leftPane)
		ui.Column(c).Grow(1).MinWidth(0).Gap(14).Children(rightPane)
	})
}
