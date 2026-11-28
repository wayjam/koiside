package shell

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"koiside/internal/device"
	"koiside/internal/installer"
	"koiside/internal/signing"
	"koiside/locales"
)

func (m *Model) hasConnectedDevice() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.devices) > 0 && m.deviceErr == ""
}

func (m *Model) sideloadedApps() []device.InstalledApp {
	m.mu.Lock()
	apps := append([]device.InstalledApp(nil), m.deviceApps...)
	side := m.sideStoreApp
	lc := m.lcApp
	queried := m.appsQueried
	m.mu.Unlock()
	if !queried {
		return nil
	}
	var out []device.InstalledApp
	for _, a := range apps {
		isDev := strings.Contains(a.Signer, "Developer") || strings.Contains(a.Signer, "Development")
		sameSideStoreTeam := side != nil && side.TeamID != "" && a.TeamID == side.TeamID
		sameLCTeam := lc != nil && lc.TeamID != "" && a.TeamID == lc.TeamID
		if isDev || sameSideStoreTeam || sameLCTeam {
			out = append(out, a)
		}
	}
	return out
}

func (m *Model) managedRecordsMap() map[string]installer.Record {
	store := m.recordStore()
	if store == nil {
		return nil
	}
	records := store.List()
	out := make(map[string]installer.Record, len(records))
	for _, r := range records {
		out[r.InstalledID] = r
	}
	return out
}

func (m *Model) findInstalledConflict(bundleID string) (device.InstalledApp, bool) {
	id := strings.TrimSpace(bundleID)
	if id == "" {
		return device.InstalledApp{}, false
	}
	m.mu.Lock()
	queried := m.appsQueried
	apps := append([]device.InstalledApp(nil), m.deviceApps...)
	m.mu.Unlock()
	if !queried {
		return device.InstalledApp{}, false
	}
	for _, a := range apps {
		if a.BundleID == id {
			return a, true
		}
		if a.TeamID != "" && a.BundleID == id+"."+a.TeamID {
			return a, true
		}
	}
	return device.InstalledApp{}, false
}
func (m *Model) findInstalledLCApp(bundleID string) (device.LiveContainerApp, bool) {
	id := strings.TrimSpace(bundleID)
	if id == "" {
		return device.LiveContainerApp{}, false
	}
	m.mu.Lock()
	lcApps := append([]device.LiveContainerApp(nil), m.lcApps...)
	m.mu.Unlock()
	for _, a := range lcApps {
		if strings.EqualFold(a.BundleID, id) {
			return a, true
		}
	}
	return device.LiveContainerApp{}, false
}

// RefreshDevices runs a read-only usbmuxd/lockdown/installation_proxy probe asynchronously.
func (m *Model) RefreshDevices() {
	m.detectDevices()
}

// StartDeviceWatch subscribes to usbmuxd attach/detach events and refreshes device state automatically.
func (m *Model) StartDeviceWatch(ctx context.Context) {
	if ctx == nil {
		return
	}
	go func() {
		var timer *time.Timer
		trigger := make(chan struct{}, 1)
		go func() {
			for {
				select {
				case <-ctx.Done():
					if timer != nil {
						timer.Stop()
					}
					return
				case <-trigger:
					if timer != nil {
						timer.Stop()
					}
					timer = time.AfterFunc(250*time.Millisecond, func() {
						if ctx.Err() == nil {
							m.detectDevices()
						}
					})
				}
			}
		}()
		device.Watch(ctx, func() {
			select {
			case trigger <- struct{}{}:
			default:
			}
		})
	}()
}

func (m *Model) detectDevices() {
	m.mu.Lock()
	if m.deviceProbing {
		m.mu.Unlock()
		return
	}
	m.deviceProbing = true
	m.mu.Unlock()

	m.addLog("device probe started")
	if m.win != nil {
		mygo.RunOnMain(func() { m.win.Invalidate() })
	}
	go func() {
		snap, err := device.ProbeFirst(nil)
		mygo.RunOnMain(func() {
			m.mu.Lock()
			m.deviceProbing = false
			m.mu.Unlock()
			m.SetSnapshot(snap, err)
		})
	}()
}

// SetSnapshot updates the UI state from a read-only device.ProbeFirst result.
func (m *Model) SetSnapshot(snap device.Snapshot, err error) {
	m.mu.Lock()
	if err != nil {
		m.devices = nil
		m.deviceErr = err.Error()
		m.deviceInfo = device.Info{}
		m.deviceApps = nil
		m.appsQueried = false
		m.sideStoreApp = nil
		m.sideStoreEmbedded = false
		m.vpnApp = nil
		m.lcApp = nil
		m.lcApps = nil
		m.latestSideStoreLog = nil
		m.sideStoreDocs = nil
		m.sideStoreTree = nil
		m.docsBundleID = ""
		m.usbVerified = false
		m.devModeKnown = false
		m.devModeEnabled = false
		m.sessionErr = nil
		m.transferrer = nil
	} else if snap.Device.ID == 0 && snap.Device.UDID == "" {
		m.devices = nil
		m.deviceErr = ""
		m.deviceInfo = device.Info{}
		m.deviceApps = nil
		m.appsQueried = false
		m.sideStoreApp = nil
		m.sideStoreEmbedded = false
		m.vpnApp = nil
		m.lcApp = nil
		m.lcApps = nil
		m.latestSideStoreLog = nil
		m.sideStoreDocs = nil
		m.sideStoreTree = nil
		m.docsBundleID = ""
		m.usbVerified = false
		m.devModeKnown = false
		m.devModeEnabled = false
		m.sessionErr = nil
		m.transferrer = nil
	} else {
		m.devices = []device.Device{snap.Device}
		m.deviceErr = ""
		m.deviceInfo = snap.Info
		m.deviceApps = append([]device.InstalledApp(nil), snap.Apps...)
		m.appsQueried = snap.SessionErr == nil && len(snap.Apps) > 0
		m.sideStoreApp = snap.SideStore
		m.sideStoreEmbedded = snap.SideStoreEmbedded
		if !m.sideStoreEmbedded && snap.SideStore == nil && snap.LiveContainer != nil {
			if snap.LatestSideStoreLog != nil {
				m.sideStoreEmbedded = true
			} else {
				for _, node := range snap.SideStoreTree {
					if node.IsDir && strings.EqualFold(node.Name, "SideStore") {
						m.sideStoreEmbedded = true
						break
					}
				}
			}
		}
		m.vpnApp = snap.LocalDevVPN
		m.lcApp = snap.LiveContainer
		m.lcApps = append([]device.LiveContainerApp(nil), snap.LiveContainerApps...)
		m.latestSideStoreLog = snap.LatestSideStoreLog
		m.sideStoreDocs = append([]string(nil), snap.SideStoreDocs...)
		m.sideStoreTree = append([]device.DocEntry(nil), snap.SideStoreTree...)
		m.docsBundleID = snap.DocsBundleID
		if m.docsBundleID == "" {
			if snap.SideStore != nil {
				m.docsBundleID = snap.SideStore.BundleID
			} else if snap.LiveContainer != nil {
				m.docsBundleID = snap.LiveContainer.BundleID
			}
		}
		m.usbVerified = snap.USBVerified
		m.devModeKnown = snap.DeveloperModeKnown
		m.devModeEnabled = snap.DeveloperModeEnabled
		m.sessionErr = snap.SessionErr
		if snap.USBVerified && snap.SideStore != nil {
			m.transferrer = device.USBTransfer{
				DeviceID: snap.Device.ID,
				UDID:     snap.Device.UDID,
				BundleID: snap.SideStore.BundleID,
			}
		} else if snap.USBVerified && snap.LiveContainer != nil {
			m.transferrer = device.USBTransfer{
				DeviceID: snap.Device.ID,
				UDID:     snap.Device.UDID,
				BundleID: snap.LiveContainer.BundleID,
			}
		} else {
			m.transferrer = nil
		}
	}
	m.mu.Unlock()

	if err != nil {
		m.addLog("device probe error")
	} else if snap.Device.ID == 0 {
		m.addLog("device disconnected")
	} else {
		m.addLog("device snapshot updated")
	}
	if m.win != nil {
		m.win.Invalidate()
	}
}

func (m *Model) deviceStatusText(msg locales.Messages) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.deviceErr != "":
		return msg.DeviceQueryFailed()
	case len(m.devices) == 0:
		return msg.DeviceDisconnected()
	default:
		for _, item := range m.devices {
			if item.ConnectionType == "USB" {
				return msg.DeviceConnectedUSB()
			}
		}
		return msg.DeviceConnectedUnknown()
	}
}

func (m *Model) sideStoreSummaryText(msg locales.Messages) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.appsQueried {
		return msg.DeviceSideStoreSummary()
	}
	if m.sideStoreApp != nil {
		return msg.DeviceSideStoreDetected()
	}
	if m.sideStoreEmbedded {
		return msg.DeviceSideStoreEmbedded()
	}
	return msg.DeviceSideStoreNotDetected()
}

// SetDevices replaces the discovered device state. Missing fields stay unknown.
func (m *Model) SetDevices(devices []device.Device, err error) {
	m.mu.Lock()
	m.devices = append([]device.Device(nil), devices...)
	m.deviceErr = ""
	if err != nil {
		m.deviceErr = err.Error()
	}
	m.mu.Unlock()
	if err != nil {
		m.addLog("device query error")
	} else {
		m.addLog("device list updated")
	}
	if m.win != nil {
		m.win.Invalidate()
	}
}

// Transferrer supplies the USB document handoff. Tests use a fake.
type Transferrer interface {
	PutIPA(source string) (device.Transfer, error)
}

// SetTransfer records a verified handoff. An error stays a transfer failure.
func (m *Model) SetTransfer(source string, transfer device.Transfer, err error) {
	m.mu.Lock()
	m.transferring = false
	if err != nil {
		m.transferState = "failed"
		m.transferErr = err.Error()
		m.transfer = "交接失败"
	} else {
		m.transferState = "done"
		m.transferErr = ""
		m.transfer = "文件已传送，尚未安装"
	}
	m.mu.Unlock()
	if err != nil {
		m.addLog("transfer failed: " + filepath.Base(source))
	} else {
		m.addLog("transfer verified: " + filepath.Base(transfer.Path))
	}
	if m.win != nil {
		m.win.Invalidate()
	}
}

func (m *Model) transferStatusText(msg locales.Messages) string {
	m.mu.Lock()
	state := m.transferState
	legacy := m.transfer
	inProgress := m.transferring
	errDetail := m.transferErr
	m.mu.Unlock()
	if inProgress {
		return msg.TransferInProgress()
	}
	if state == "" {
		switch legacy {
		case "文件已传送，尚未安装":
			state = "done"
		case "交接失败":
			state = "failed"
		}
	}
	switch state {
	case "done":
		return msg.TransferStatusPrefix(msg.TransferDoneNotInstalled())
	case "failed":
		if errDetail != "" {
			return msg.TransferErrorDetail(friendlyError(msg, errDetail))
		}
		return msg.TransferStatusPrefix(msg.TransferFailed())
	default:
		return msg.TransferNotStarted()
	}
}

func (m *Model) handoffSelected() {
	m.mu.Lock()
	busy := m.transferring
	tr := m.transferrer
	m.mu.Unlock()
	if busy {
		return
	}
	file, ok := m.selectedArchive()
	if !ok || file.err != "" || tr == nil {
		m.SetTransfer("", device.Transfer{}, device.ErrUnavailable)
		return
	}
	targetPath := m.effectiveArchivePath(file)
	if m.win == nil {
		if prepared, prepErr := m.ensurePreparedArchivePath(file); prepErr == nil && prepared != "" {
			targetPath = prepared
		}
		result, err := tr.PutIPA(targetPath)
		m.SetTransfer(targetPath, result, err)
		return
	}
	m.mu.Lock()
	m.transferring = true
	m.transferErr = ""
	m.mu.Unlock()
	m.win.Invalidate()
	go func() {
		prepared, prepErr := m.ensurePreparedArchivePath(file)
		if prepErr != nil {
			mygo.RunOnMain(func() {
				m.SetTransfer(targetPath, device.Transfer{}, prepErr)
			})
			return
		}
		if prepared != "" {
			targetPath = prepared
		}
		result, err := tr.PutIPA(targetPath)
		mygo.RunOnMain(func() {
			m.SetTransfer(targetPath, result, err)
		})
	}()
}

func (m *Model) filteredDeviceApps() []device.InstalledApp {
	sideloaded := m.sideloadedApps()
	m.mu.Lock()
	all := append([]device.InstalledApp(nil), m.deviceApps...)
	filter := m.appFilter
	q := strings.ToLower(strings.TrimSpace(m.appQuery))
	m.mu.Unlock()

	managedMap := m.managedRecordsMap()
	source := all
	switch filter {
	case 2:
		var managed []device.InstalledApp
		for _, a := range sideloaded {
			if _, ok := managedMap[a.BundleID]; ok {
				managed = append(managed, a)
			}
		}
		source = managed
	case 1:
		source = sideloaded
	}
	if q == "" {
		return source
	}
	var out []device.InstalledApp
	for _, a := range source {
		if strings.Contains(strings.ToLower(a.Name), q) ||
			strings.Contains(strings.ToLower(a.BundleID), q) ||
			strings.Contains(strings.ToLower(a.TeamID), q) ||
			strings.Contains(strings.ToLower(a.Signer), q) {
			out = append(out, a)
		}
	}
	return out
}

func (m *Model) docTreeView(c *ui.Context, msg locales.Messages, entries []device.DocEntry, depth int) {
	t := c.Theme()
	for _, entry := range entries {
		entry := entry
		indent := float32(18 + depth*18)
		if entry.IsDir {
			open := m.docTreeOpen[entry.Path]
			row := ui.ButtonBase(c.Key("doc-dir-"+entry.Path)).FillWidth().
				Padding(8, 18, 8, indent).Background(t.Surface).
				Label(entry.Name).Cursor(ui.CursorPointer).Transition(colorTransition)
			if row.Hovered() {
				row.Background(t.SurfaceHover)
			}
			applyPressPose(row, 0.992)
			row.Children(func() {
				ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
					chevPose := ui.Pose{}
					if open {
						chevPose = ui.Pose{Rotate: 90}
					}
					ui.Icon(c.Key("doc-chev-"+entry.Path), phCaretRight).Width(13).Height(13).TextColor(t.TextMuted).AnimatePose(chevPose, ui.Snappy)
					ui.Icon(c, phFolderFill).Width(15).Height(15).TextColor(accentInk(t))
					ui.Text(c, entry.Name).Bold().FontSize(12).Grow(1)
					ui.Text(c, msg.DeviceDocsItemsCount(len(entry.Children))).FontSize(11).TextColor(t.TextMuted)
				})
			})
			if row.Clicked() {
				m.docTreeOpen[entry.Path] = !open
			}
			ui.Column(c.Key("doc-branch-" + entry.Path)).FillWidth().Clip().Transition(heightTransition).Children(func() {
				if open {
					if len(entry.Children) == 0 {
						ui.Row(c).FillWidth().Padding(6, 18, 6, indent+22).Children(func() {
							ui.Text(c, msg.DeviceDocsEmpty()).FontSize(11).TextColor(t.TextMuted)
						})
					} else {
						m.docTreeView(c, msg, entry.Children, depth+1)
					}
				}
			})
			continue
		}

		icon := phFileText
		if strings.HasSuffix(strings.ToLower(entry.Name), ".ipa") {
			icon = phFileArchive
		}
		ui.Row(c.Key("doc-file-"+entry.Path)).FillWidth().Padding(7, 18, 7, indent+18).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, icon).Width(15).Height(15).TextColor(t.TextMuted)
			monoText(c, entry.Name).FontSize(12).Grow(1)
			monoText(c, formatBytes(entry.Size)).FontSize(11).TextColor(t.TextMuted)
			if isDeletableDocFile(entry.Path, entry.Name) && m.docsBundleID != "" {
				m.mu.Lock()
				deleting := m.docDeleting == entry.Path
				m.mu.Unlock()
				noDev := !m.hasConnectedDevice()
				delTip := ""
				if noDev {
					delTip = msg.ToolInstallNeedDevice()
				}
				delBtn := uiBtnWithTip(c, "doc-del-"+entry.Path, msg.DeviceDocDeleteBtn(), deleting || noDev, delTip)
				if delBtn.Clicked() {
					m.deleteDeviceDoc(entry.Path, entry.Name)
				}
			}
		})
	}
}

func isDeletableDocFile(_, name string) bool {
	low := strings.ToLower(name)
	if strings.HasSuffix(low, ".ipa") || strings.HasSuffix(low, ".partial") {
		return true
	}
	return false
}

func (m *Model) deleteDeviceDoc(remotePath, name string) {
	m.mu.Lock()
	if len(m.devices) == 0 || m.docsBundleID == "" || m.docDeleting != "" {
		m.mu.Unlock()
		return
	}
	dev := m.devices[0]
	bundleID := m.docsBundleID
	m.docDeleting = remotePath
	m.docDeleteErr = ""
	m.docDeleteMsg = ""
	m.mu.Unlock()
	go func() {
		err := device.RemoveDocPath(nil, dev.ID, dev.UDID, bundleID, remotePath)
		curMsg := m.msg(nil)
		m.mu.Lock()
		m.docDeleting = ""
		if err != nil {
			m.docDeleteErr = err.Error()
		} else {
			m.docDeleteMsg = curMsg.DeviceDocDeleted(name)
		}
		m.mu.Unlock()
		if err == nil {
			m.addLog("deleted device doc: " + remotePath)
			m.detectDevices()
		} else if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}
func (m *Model) transferIPAPathToDevice(targetPath string) {
	m.mu.Lock()
	busy := m.transferring
	tr := m.transferrer
	m.mu.Unlock()
	if busy || tr == nil || targetPath == "" {
		return
	}
	if m.win == nil {
		result, err := tr.PutIPA(targetPath)
		m.SetTransfer(targetPath, result, err)
		m.detectDevices()
		return
	}
	m.mu.Lock()
	m.transferring = true
	m.transferErr = ""
	m.mu.Unlock()
	m.win.Invalidate()
	go func() {
		result, err := tr.PutIPA(targetPath)
		mygo.RunOnMain(func() {
			m.SetTransfer(targetPath, result, err)
			m.detectDevices()
		})
	}()
}

func (m *Model) pickIPAToDevice() {
	if m.win == nil {
		return
	}
	win := m.win
	title := m.msg(nil).DeviceDocsImportIPABtn()
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Parent:   win,
			Title:    title,
			Filters:  []mygo.FileFilter{{Name: "iOS App", Extensions: []string{"ipa"}}},
			Multiple: false,
		})
		if err == nil && len(paths) > 0 {
			win.Update(func() {
				m.transferIPAPathToDevice(paths[0])
			})
		}
	}()
}

func (m *Model) deviceView(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.DeviceTitle()).FontSize(26).Bold()
		ui.Text(c, msg.DeviceSubtitle()).TextColor(t.TextMuted)
	})

	if !m.hasConnectedDevice() {
		surfaceCard(c, "device-disconnected-card").Padding(26, 24).Gap(12).AlignItems(ui.Center).Children(func() {
			ui.Image(c, phDeviceSlashDuotone).Width(56).Height(56).TextColor(t.TextMuted)
			ui.Text(c, msg.DeviceDisconnectedTitle()).FontSize(18).Bold()
			ui.Text(c.Key("device-page-status"), m.deviceStatusText(msg)).FontSize(13).TextColor(t.TextMuted)
			ui.Text(c, msg.DeviceNoIPhoneHint()).FontSize(12).TextColor(t.TextMuted)
			ui.Row(c).Gap(10).Children(func() {
				if uiPrimaryBtn(c, "device-refresh", msg.DeviceRefresh()).Clicked() {
					m.detectDevices()
				}
				if uiBtn(c, "device-work-offline", msg.DeviceWorkOffline()).Clicked() {
					m.goTaskSection("文件", 1)
				}
				if uiBtn(c, "device-connect-help", msg.NeedHelp()).Clicked() {
					m.openHelp("connect")
				}
			})
		})
	} else {
		dev := m.devices[0]
		surfaceCard(c, "device-main-card").Padding(18, 20).Children(func() {
			ui.Row(c).FillWidth().Gap(16).AlignItems(ui.Center).Children(func() {
				ui.Image(c, phoneBadgeSVG).Width(32).Height(54)
				ui.Column(c).Grow(1).Gap(4).Children(func() {
					title := msg.DeviceCardTitle()
					if m.deviceInfo.Name != "" {
						title = m.deviceInfo.Name
					}
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Text(c, title).Bold().FontSize(18)
						ui.Row(c).Width(8).Height(8).Radius(4).Background(ui.Hex("#10B981"))
					})
					ui.Text(c.Key("device-page-status"), m.deviceStatusText(msg)).FontSize(14).TextColor(t.TextMuted)
					monoText(c, msg.DeviceConnectionType(valueOrUnknown(msg, dev.ConnectionType))).FontSize(12).TextColor(t.TextMuted)
					if m.deviceInfo.Type != "" || m.deviceInfo.Version != "" {
						ver := valueOrUnknown(msg, m.deviceInfo.Version)
						if m.deviceInfo.Build != "" {
							ver += " (" + m.deviceInfo.Build + ")"
						}
						monoText(c, msg.DeviceModelVersion(valueOrUnknown(msg, m.deviceInfo.Type), ver)).FontSize(12).TextColor(t.TextMuted)
					}
					devModeLabel := msg.DeviceDevModeUnknown()
					devModeColor := t.TextMuted
					if m.devModeKnown {
						if m.devModeEnabled {
							devModeLabel = msg.DeviceDevModeOn()
							devModeColor = ui.Hex("#10B981")
						} else {
							devModeLabel = msg.DeviceDevModeOff()
							devModeColor = ui.Hex("#F59E0B")
						}
					}
					ui.Text(c.Key("device-devmode-status"), devModeLabel).FontSize(12).Bold().TextColor(devModeColor)
					if m.devModeErr != "" {
						ui.Text(c, msg.DeviceDevModeFailed(friendlyError(msg, m.devModeErr))).FontSize(11).TextColor(ui.Hex("#EF4444"))
					} else if m.devModeMsg != "" {
						ui.Text(c, m.devModeMsg).FontSize(11).TextColor(accentInk(t))
					}
					if m.sessionErr != nil {
						hint := m.sessionErr.Error()
						if errors.Is(m.sessionErr, device.ErrLocked) {
							hint = msg.DeviceSessionLocked()
						} else if errors.Is(m.sessionErr, device.ErrUntrusted) {
							hint = msg.DeviceSessionUntrusted()
						}
						ui.Text(c, friendlyError(msg, hint)).FontSize(12).TextColor(ui.Hex("#F59E0B"))
					}
				})
				ui.Column(c).Gap(6).AlignItems(ui.End).Children(func() {
					if uiBtn(c, "device-refresh", msg.DeviceRefresh()).Clicked() {
						m.detectDevices()
					}
					if !m.devModeKnown || !m.devModeEnabled {
						if uiBtn(c, "device-enable-devmode", msg.DeviceDevModeEnableBtn()).Clicked() {
							m.triggerDeveloperMode()
						}
					}
				})
			})
		})
	}

	ui.Row(c.Key("device-tabs-row")).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Segmented(c.Key("device-sub-tab"), &m.deviceTab,
			msg.DeviceTabEnvironment(),
			msg.DeviceTabApps(),
			msg.DeviceTabDocs(),
		).Cursor(ui.CursorPointer).Label(msg.DeviceTitle())
	})

	switch m.deviceTab {
	case 1:
		m.renderDeviceApps(c, msg)
	case 2:
		m.renderDeviceDocs(c, msg)
	default:
		m.renderDeviceEnvironment(c, msg)
	}
}

func (m *Model) renderDeviceEnvironment(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	toolStatusText := func(app *device.InstalledApp) string {
		if !m.appsQueried {
			return msg.DeviceSideStoreStatusUnknown()
		}
		if app != nil {
			return msg.DeviceToolDetected(valueOrUnknown(msg, app.Version))
		}
		return msg.DeviceToolNotDetected()
	}

	winW, _ := c.Size()
	stackToolRow := winW > 0 && winW < mediumWidth

	insetGroup(c, "device-sidestore-group", func() {
		renderSSInfo := func() {
			ui.Row(c).Width(40).Height(40).Radius(10).Background(t.Accent).Shrink(0).
				InsetShadow(0, 1, 0, 0, ui.RGBA(255, 255, 255, 0.22)).
				Center().Children(func() {
				ui.Icon(c, phLightningFill).Width(20).Height(20).TextColor(ui.Hex("#FFFFFF"))
			})
			ui.Column(c).Grow(1).MinWidth(0).Gap(3).Children(func() {
				ui.Row(c).FillWidth().Wrap().Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Text(c, msg.DeviceSideStoreCardTitle()).Bold().FontSize(15)
					sideStatus := toolStatusText(m.sideStoreApp)
					if m.appsQueried && m.sideStoreApp == nil && m.sideStoreEmbedded {
						sideStatus = msg.DeviceToolEmbeddedInLC()
					}
					ui.Text(c.Key("device-sidestore-status"), sideStatus).Role(ui.RoleStatus).FontSize(12).TextColor(t.TextMuted)
				})
				if m.sideStoreApp != nil {
					monoText(c, msg.LibraryBundleID()+": "+m.sideStoreApp.BundleID).FontSize(11).TextColor(t.TextMuted)
				} else if m.sideStoreEmbedded && m.lcApp != nil {
					monoText(c, msg.LibraryBundleID()+": "+m.lcApp.BundleID).FontSize(11).TextColor(t.TextMuted)
				}
				if m.usbVerified {
					ui.Text(c, msg.DeviceSideStoreUSBReady()).FontSize(12).TextColor(accentInk(t))
				} else {
					ui.Text(c, msg.DeviceSideStoreDesc()).FontSize(12).TextColor(t.TextMuted)
				}
				m.mu.Lock()
				latestLog := m.latestSideStoreLog
				m.mu.Unlock()
				if latestLog != nil && latestLog.Operation != "" {
					st := latestLog.Status
					if st == "" {
						st = "unknown"
					}
					monoText(c.Key("device-latest-ss-log"), msg.DeviceLatestSideStoreLog(latestLog.Operation, st, latestLog.File)).Role(ui.RoleStatus).FontSize(11).TextColor(t.TextMuted)
				}
			})
		}
		renderSSActions := func() {
			ui.Row(c).Wrap().Gap(8).Children(func() {
				if m.deviceBtn(c, msg, "install-sidestore-btn", msg.ToolInstallSideStoreBtn(), false, false).Clicked() {
					m.confirmToolInstall(installer.TargetSideStore)
				}
				if uiBtn(c, "sidestore-guide", msg.DeviceViewToolGuide()).Clicked() {
					m.openHelp("setup")
				}
			})
		}
		if stackToolRow {
			ui.Column(c).FillWidth().Padding(14, 16).Gap(10).Children(func() {
				ui.Row(c).FillWidth().Gap(12).AlignItems(ui.Start).Children(renderSSInfo)
				ui.Row(c).FillWidth().Justify(ui.End).Children(renderSSActions)
			})
		} else {
			ui.Row(c).FillWidth().Padding(16, 18).Gap(14).AlignItems(ui.Center).Children(func() {
				renderSSInfo()
				renderSSActions()
			})
		}
		ui.Divider(c)
		ui.Row(c).FillWidth().Wrap().Padding(10, 18).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Row(c).Gap(6).AlignItems(ui.Center).Grow(1).MinWidth(180).Children(func() {
				ui.Icon(c, phShieldFill).Width(15).Height(15).TextColor(ui.Hex("#0284C7"))
				ui.Text(c, "LocalDevVPN").Bold().FontSize(12)
				ui.Text(c, toolStatusText(m.vpnApp)).FontSize(12).TextColor(t.TextMuted)
			})
			if uiBtn(c, "device-localdevvpn-appstore", msg.ToolInstallLocalDevVPNBtn()).Clicked() {
				c.OpenURL("https://apps.apple.com/app/localdevvpn/id6755608044")
			}
		})
		ui.Divider(c)
		ui.Row(c).FillWidth().Wrap().Padding(10, 18).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Row(c).Gap(6).AlignItems(ui.Center).Grow(1).MinWidth(180).Children(func() {
				ui.Icon(c, phCubeFill).Width(15).Height(15).TextColor(ui.Hex("#0D9488"))
				ui.Text(c, "LiveContainer").Bold().FontSize(12)
				ui.Text(c, toolStatusText(m.lcApp)).FontSize(12).TextColor(t.TextMuted)
			})
			ui.Row(c).Wrap().Gap(8).Children(func() {
				if m.deviceBtn(c, msg, "install-lcss-btn", msg.ToolInstallLCSSBtn(), false, false).Clicked() {
					m.confirmToolInstall(installer.TargetLiveContainerLCSS)
				}
				if m.deviceBtn(c, msg, "install-lc-btn", msg.ToolInstallLCBtn(), false, false).Clicked() {
					m.confirmToolInstall(installer.TargetLiveContainerOnly)
				}
			})
		})
		m.toolInstallStatusRow(c, msg)
	})

	insetGroup(c, "device-pairing-group", func() {
		ui.Column(c).FillWidth().Padding(14, 18).Gap(10).Children(func() {
			ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phKey).Width(18).Height(18).TextColor(accentInk(t))
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, msg.PairingSectionTitle()).Bold().FontSize(14)
					ui.Text(c, msg.PairingSectionDesc()).FontSize(12).TextColor(t.TextMuted)
				})
				if m.deviceBtn(c, msg, "device-pairing-export", msg.PairingExportBtn(), false, false).Clicked() {
					m.exportPairingToFile()
				}
				placeBtn := m.deviceBtn(c, msg, "device-pairing-place", msg.PairingOneClickBtn(), false, m.pairingBusy)
				if placeBtn.Clicked() {
					m.placePairingToAll()
				}
			})
			m.mu.Lock()
			pBusy := m.pairingBusy
			pMsg := m.pairingMsg
			pErr := m.pairingErr
			m.mu.Unlock()
			if pBusy {
				ui.Spinner(c).Label(msg.PairingOneClickBtn())
			} else if pErr != "" {
				ui.Text(c, msg.PairingWriteFailed(friendlyError(msg, pErr))).FontSize(11).TextColor(ui.Hex("#EF4444"))
			} else if pMsg != "" {
				ui.Text(c, pMsg).FontSize(11).TextColor(ui.Hex("#10B981"))
			}
		})
	})
}

func (m *Model) renderDeviceApps(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	insetGroup(c, "device-installed-apps-group", func() {
		sideloaded := m.sideloadedApps()
		ui.Column(c).FillWidth().Padding(16, 18).Gap(8).Children(func() {
			ui.Text(c, msg.DeviceInstalledAppsTitle()).Bold().FontSize(15)
			ui.Text(c, msg.DeviceInstalledAppsDesc()).FontSize(12).TextColor(t.TextMuted)
			if !m.appsQueried {
				ui.Text(c, msg.DeviceInstalledAppsEmpty()).FontSize(12).TextColor(t.TextMuted)
			} else {
				ui.Text(c, msg.DeviceAppsSummary(len(m.deviceApps), len(sideloaded))).FontSize(12).Bold().TextColor(accentInk(t))
				ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Row(c).Grow(1).Gap(8).AlignItems(ui.Center).Padding(0, 10, 0, 0).Children(func() {
						ui.Icon(c, phSearch).Width(15).Height(15).TextColor(t.TextMuted)
						ui.TextInput(c.Key("device-app-search"), &m.appQuery).
							Placeholder(msg.DeviceAppsSearchPlaceholder()).
							FillWidth().Label(msg.DeviceAppsSearchPlaceholder())
					})
					managedMap := m.managedRecordsMap()
					managedCount := 0
					for _, a := range sideloaded {
						if _, ok := managedMap[a.BundleID]; ok {
							managedCount++
						}
					}
					ui.Segmented(c.Key("device-app-filter"), &m.appFilter,
						msg.DeviceAppsFilterAll(len(m.deviceApps)),
						msg.DeviceAppsFilterSideloaded(len(sideloaded)),
						msg.DeviceAppsFilterManaged(managedCount),
					).Cursor(ui.CursorPointer).Label(msg.DeviceInstalledAppsTitle())
				})
			}
		})
		if m.appsQueried {
			shown := m.filteredDeviceApps()
			ui.Divider(c)
			if len(shown) == 0 {
				ui.Row(c).FillWidth().Padding(14, 18).Children(func() {
					ui.Text(c, msg.DeviceAppsNoMatch()).FontSize(12).TextColor(t.TextMuted)
				})
			} else {
				ui.Scroll(c.Key("device-apps-scroll")).FillWidth().MaxHeight(360).Children(func() {
					for idx, a := range shown {
						if idx > 0 {
							ui.Divider(c)
						}
						managedMap := m.managedRecordsMap()
						rec, isManaged := managedMap[a.BundleID]
						ui.Row(c.Key(fmt.Sprintf("app-row-%d-%s", idx, a.BundleID))).FillWidth().Padding(10, 18).AlignItems(ui.Center).Gap(10).Children(func() {
							ui.Column(c).Width(156).Gap(1).Children(func() {
								ui.Text(c, valueOrUnknown(msg, a.Name)).Bold().FontSize(12).SingleLine()
								if a.TeamID != "" {
									monoText(c, "Team "+a.TeamID).FontSize(10).TextColor(t.TextMuted)
								}
							})
							monoText(c, a.BundleID).FontSize(11).TextColor(t.TextMuted).Grow(1)
							if isManaged && !rec.ProfileExpiry.IsZero() {
								now := time.Now().UTC()
								if rec.ProfileExpiry.Before(now) {
									ui.Text(c, msg.DeviceAppsExpired()).FontSize(11).Bold().TextColor(ui.Hex("#EF4444"))
								} else {
									rem := rec.ProfileExpiry.Sub(now)
									days := int(rem.Hours() / 24)
									hours := int(rem.Hours()) % 24
									text := msg.DeviceAppsDaysLeft(days)
									if days == 0 {
										text = msg.DeviceAppsHoursLeft(hours)
									}
									col := successInk(t)
									if days <= 1 {
										col = ui.Hex("#F59E0B")
									}
									ui.Text(c, text).FontSize(11).Bold().TextColor(col)
								}
								renewBtn := uiBtn(c, fmt.Sprintf("renew-btn-%s", a.BundleID), msg.DeviceAppsRenewBtn())
								if renewBtn.Clicked() {
									m.renewAppProfile(rec)
								}
							} else {
								monoText(c, valueOrUnknown(msg, a.Version)).FontSize(11).TextColor(t.TextMuted)
							}
						})
					}
				})
			}
		}
	})
}

func (m *Model) renderDeviceDocs(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	insetGroup(c, "device-docs-group", func() {
		count := len(m.sideStoreTree)
		if count == 0 {
			count = len(m.sideStoreDocs)
		}
		docsTitle := msg.DeviceDocsTitle()
		if m.sideStoreApp == nil && m.lcApp != nil && m.docsBundleID == m.lcApp.BundleID {
			docsTitle = msg.DeviceLCDocsTitle()
		}
		ui.Row(c).FillWidth().Padding(14, 18).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, phFolderOpen).Width(18).Height(18).TextColor(accentInk(t))
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, docsTitle).Bold().FontSize(14)
				m.mu.Lock()
				delMsg := m.docDeleteMsg
				delErr := m.docDeleteErr
				m.mu.Unlock()
				if delErr != "" {
					ui.Text(c, friendlyError(msg, delErr)).FontSize(11).TextColor(ui.Hex("#EF4444"))
				} else if delMsg != "" {
					ui.Text(c, delMsg).FontSize(11).TextColor(ui.Hex("#10B981"))
				}
			})
			ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Text(c, msg.DeviceDocsItemsCount(count)).FontSize(12).TextColor(t.TextMuted)
				noDev := !m.hasConnectedDevice()
				devTip := ""
				if noDev {
					devTip = msg.ToolInstallNeedDevice()
				}
				if uiBtnWithTip(c, "device-docs-import-ipa", msg.DeviceDocsImportIPABtn(), noDev, devTip).Clicked() {
					m.pickIPAToDevice()
				}
			})
		})
		ui.Divider(c)
		dropBox := ui.Column(c.Key("device-docs-dropzone")).FillWidth().Padding(12, 18).Gap(6).
			Background(t.Selection).Border(1, accentInk(t).Alpha(0.3)).Radius(8).
			Transition(dropZoneTransition)
		if dropBox.FileDragOver() {
			dropBox.Border(2, accentInk(t)).InsetShadow(0, 0, 0, 2, accentInk(t).Alpha(0.25))
		}
		if files := dropBox.DroppedFiles(); len(files) > 0 {
			for _, f := range files {
				if strings.HasSuffix(strings.ToLower(f), ".ipa") {
					m.transferIPAPathToDevice(f)
					break
				}
			}
		}
		dropBox.Children(func() {
			ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phExport).Width(16).Height(16).TextColor(accentInk(t))
				ui.Text(c, msg.DeviceDocsDropHint()).FontSize(12).TextColor(accentInk(t)).Grow(1)
				m.mu.Lock()
				transferring := m.transferring
				transferErr := m.transferErr
				transferState := m.transferState
				m.mu.Unlock()
				complete := !transferring && transferState == "done"
				if transferring || complete {
					label := msg.TransferInProgress()
					if complete {
						label = msg.HandoffStageBadgeTransferred()
					}
					deliveryProgress(c, "docs-transfer-progress", label, -1, complete).Width(48)
				}
				if complete {
					ui.Text(c, msg.HandoffStageBadgeTransferred()).FontSize(11).Bold().TextColor(successInk(t))
				} else if transferring {
					ui.Text(c, msg.TransferInProgress()).FontSize(11).TextColor(accentInk(t))
				} else if transferErr != "" {
					ui.Text(c, msg.TransferErrorDetail(friendlyError(msg, transferErr))).FontSize(11).TextColor(ui.Hex("#EF4444"))
				}
			})
		})
		ui.Divider(c)
		if !m.usbVerified {
			ui.Row(c).FillWidth().Padding(14, 18).Children(func() {
				ui.Text(c, msg.TransferUSBUnverified()).FontSize(12).TextColor(t.TextMuted)
			})
		} else {
			ui.Scroll(c.Key("device-docs-scroll")).FillWidth().MaxHeight(260).Children(func() {
				if len(m.sideStoreTree) > 0 {
					m.docTreeView(c, msg, m.sideStoreTree, 0)
				} else if len(m.sideStoreDocs) > 0 {
					for _, name := range m.sideStoreDocs {
						icon := phFileText
						if strings.HasSuffix(strings.ToLower(name), ".ipa") {
							icon = phFileArchive
						}
						remote := "/Documents/" + name
						ui.Row(c.Key("doc-flat-"+name)).FillWidth().Padding(7, 18).Gap(8).AlignItems(ui.Center).Children(func() {
							ui.Icon(c, icon).Width(15).Height(15).TextColor(t.TextMuted)
							monoText(c, name).FontSize(12).Grow(1)
							if isDeletableDocFile(remote, name) && m.docsBundleID != "" {
								noDev := !m.hasConnectedDevice()
								delTip := ""
								if noDev {
									delTip = msg.ToolInstallNeedDevice()
								}
								if uiBtnWithTip(c, "doc-flat-del-"+name, msg.DeviceDocDeleteBtn(), noDev, delTip).Clicked() {
									m.deleteDeviceDoc(remote, name)
								}
							}
						})
					}
				} else {
					ui.Row(c).FillWidth().Padding(12, 18).Children(func() {
						ui.Text(c, msg.DeviceDocsEmpty()).FontSize(12).TextColor(t.TextMuted)
					})
				}
			})
		}
	})
}

// extensionCount counts the app extensions a direct install registers.
func extensionCount(file archiveState) int {
	n := 0
	for _, comp := range file.report.Components {
		if comp.Kind == "extension" || comp.Kind == "watch-extension" {
			n++
		}
	}
	return n
}

func (m *Model) transferView(c *ui.Context, msg locales.Messages, compact bool) {
	t := c.Theme()
	m.taskHeaderAndSteps(c, msg, 4)

	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.HandoffStageTitle()).FontSize(26).Bold()
		ui.Text(c, msg.HandoffStageSubtitle()).TextColor(t.TextMuted)
	})

	file, hasFile := m.selectedArchive()
	targetFilename := "App.ipa"
	targetBundleID := ""
	if hasFile {
		targetFilename = filepath.Base(m.effectiveArchivePath(file))
		targetBundleID = m.effectiveBundleID(file)
	}
	extCount := 0
	if hasFile {
		extCount = extensionCount(file)
	}
	installedMatch, installedOnDevice := m.findInstalledConflict(targetBundleID)

	statusPill := func(label string, active bool) {
		bg := t.Surface
		fg := t.TextMuted
		border := t.Border
		if active {
			bg = t.Selection
			fg = accentInk(t)
			border = accentInk(t).Alpha(0.5)
		}
		ui.Row(c).Padding(4, 10).Radius(8).Background(bg).Border(1, border).Gap(6).AlignItems(ui.Center).Children(func() {
			if active {
				ui.Icon(c, phCheckCircleFill).Width(13).Height(13).TextColor(ui.Hex("#10B981"))
			}
			ui.Text(c, label).FontSize(11).Bold().TextColor(fg)
		})
	}
	isLC := m.installRoute == "livecontainer"
	isLCInside := isLC && m.lcPlacement != "outside"
	isDirectPreferred := m.installRoute == "advanced" || (isLC && m.lcPlacement == "outside")
	lcMatch, lcInstalled := m.findInstalledLCApp(targetBundleID)
	detectedAnywhere := installedOnDevice || (isLCInside && lcInstalled)

	ui.Row(c).FillWidth().Gap(8).Children(func() {
		statusPill(msg.HandoffStageBadgeExported(), m.exportedPath != "")
		statusPill(msg.HandoffStageBadgeTransferred(), m.transferState == "done")
		statusPill(msg.HandoffStageBadgeDetected(), detectedAnywhere)
		statusPill(msg.HandoffStageBadgeUserConfirmed(), m.userConfirmed)
	})
	mainPane := func() {
		if isLC {
			ui.Row(c).FillWidth().Padding(10, 14).Gap(10).Radius(10).
				Background(t.Selection).Border(1, accentInk(t).Alpha(0.35)).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phInfo).Width(18).Height(18).TextColor(accentInk(t))
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					if isLCInside {
						ui.Text(c, msg.HandoffPlacementBadgeInside()).Bold().FontSize(12)
					} else {
						ui.Text(c, msg.HandoffPlacementBadgeOutside()).Bold().FontSize(12)
					}
					ui.Text(c, msg.TransferLiveContainerNote()).FontSize(11).TextColor(t.TextMuted)
				})
				if isLCInside {
					if uiBtn(c, "handoff-switch-outside", msg.HandoffSwitchToOutside()).Clicked() {
						m.lcPlacement = "outside"
					}
				} else {
					if uiBtn(c, "handoff-switch-inside", msg.HandoffSwitchToInside()).Clicked() {
						m.lcPlacement = "inside"
					}
				}
			})
		}

		if hasFile {
			surfaceCard(c, "transfer-ipa-card").Padding(14, 18).Children(func() {
				ui.Row(c).FillWidth().Gap(14).AlignItems(ui.Center).Children(func() {
					appIconBadgeHero(c, file, 40)
					ui.Column(c).Grow(1).Gap(2).Children(func() {
						name := file.report.DisplayName
						if m.editName != "" && m.prepareMode == "edit" {
							name = m.editName
						}
						if name == "" {
							name = targetFilename
						}
						ui.Text(c, name).Bold().FontSize(15)
						monoText(c, msg.LibraryBundleID()+": "+valueOrUnknown(msg, targetBundleID)).FontSize(12).TextColor(t.TextMuted)
					})
				})
			})
		}

		readyToConfirm := m.transferState == "done" || detectedAnywhere
		usbBtnLabel := msg.TransferStartHandoff()
		if isLCInside {
			usbBtnLabel = msg.HandoffSendToLCBtn()
		}

		usbTransferRow := func(primary bool) {
			ui.Row(c).FillWidth().Padding(14, 18).Gap(14).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phUSB).Width(22).Height(22).TextColor(accentInk(t))
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, msg.TransferUSBStatusLabel()).Bold().FontSize(14)
					if m.usbVerified {
						ui.Text(c, msg.TransferUSBVerified()).FontSize(12).TextColor(t.TextMuted)
					} else {
						ui.Text(c, msg.TransferUSBUnverified()).FontSize(12).TextColor(t.TextMuted)
					}
					ui.Row(c).Wrap().Gap(6).AlignItems(ui.Center).Children(func() {
						status := m.transferStatusText(msg)
						complete := !m.transferring && m.transferState == "done"
						if m.transferring || complete {
							deliveryProgress(c, "usb-transfer-progress", status, -1, complete).Width(48)
						}
						statusColor := accentInk(t)
						if complete {
							statusColor = successInk(t)
						} else if m.transferState == "failed" {
							statusColor = ui.Hex("#EF4444")
						}
						ui.Text(c.Key("transfer-status-line"), status).Role(ui.RoleStatus).FontSize(12).TextColor(statusColor)
					})
				})
				handoffBtn := m.deviceBtn(c, msg, "transfer-handoff-btn", usbBtnLabel, primary && !readyToConfirm, m.transferring)
				if handoffBtn.Clicked() {
					m.handoffSelected()
				}
			})
		}

		directInstallRow := func(primary bool) {
			ui.Row(c).FillWidth().Padding(14, 18).Gap(14).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phLightningFill).Width(22).Height(22).TextColor(accentInk(t))
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, msg.TransferDirectInstallTitle()).Bold().FontSize(14)
					ui.Text(c, msg.TransferDirectInstallDesc()).FontSize(12).TextColor(t.TextMuted)
					m.mu.Lock()
					dOn := m.directInstallOn
					dPct := m.directPct
					dStage := m.directStage
					dErr := m.directErr
					dDone := m.directDoneMsg
					m.mu.Unlock()
					if dOn || dDone != "" {
						ui.Row(c).Wrap().Gap(8).AlignItems(ui.Center).Children(func() {
							stage := progressStageLabel(msg, dStage)
							if dOn {
								deliveryProgress(c, "direct-install-progress", stage, float64(dPct)/100, false).Width(160)
								ui.Text(c, msg.ToolInstallRunning(stage, dPct)).FontSize(11).TextColor(accentInk(t))
								return
							}
							deliveryProgress(c, "direct-install-progress", dDone, 1, true).Width(160)
							ui.Text(c.Key("direct-install-done"), dDone).Role(ui.RoleStatus).FontSize(11).TextColor(successInk(t)).
								Transition(feedbackBannerTransition)
						})
					} else if dErr != "" {
						ui.Text(c.Key("direct-install-err"), msg.ToolInstallFailed(friendlyError(msg, dErr))).FontSize(11).TextColor(ui.Hex("#EF4444")).
							Transition(feedbackBannerTransition)
					}
					if hasFile && extCount > 0 && !dOn {
						skip := m.skipExtensionsFor == file.path
						ui.Column(c).FillWidth().Padding(6, 0, 0, 0).Gap(3).Children(func() {
							ui.Text(c.Key("direct-ext-note"), msg.TransferExtensionsNote(extCount)).
								FontSize(11).TextColor(t.TextMuted)
							if ui.Checkbox(c.Key("direct-skip-ext"), &skip, msg.TransferSkipExtensions()).
								Cursor(ui.CursorPointer).Changed() {
								if skip {
									m.skipExtensionsFor = file.path
								} else {
									m.skipExtensionsFor = ""
								}
							}
						})
					}
				})
				directBtn := m.deviceBtn(c, msg, "transfer-direct-install-btn", msg.TransferDirectInstallBtn(), primary && !installedOnDevice, m.directInstallOn)
				if directBtn.Clicked() {
					m.directInstallSelected()
				}
			})
		}

		insetGroup(c, "transfer-methods-group", func() {
			if isDirectPreferred {
				directInstallRow(true)
				ui.Divider(c)
				usbTransferRow(false)
			} else {
				usbTransferRow(true)
				ui.Divider(c)
				directInstallRow(false)
			}
			ui.Divider(c)
			ui.Row(c).FillWidth().Padding(14, 18).Gap(14).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phExport).Width(22).Height(22).TextColor(t.TextMuted)
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, msg.TransferExportAlt()).Bold().FontSize(14)
					ui.Text(c, msg.TransferExportAltDesc()).FontSize(12).TextColor(t.TextMuted)
				})
				if uiBtn(c, "transfer-save-copy", msg.DiffExportBtn()).Clicked() {
					m.SaveCopy()
				}
			})
		})
		if m.transferState == "done" {
			surfaceCard(c, "transferred-path-card").Padding(14, 16).Gap(6).Children(func() {
				ui.Text(c, msg.HandoffDevicePathTitle()).Bold().FontSize(13)
				if isLCInside {
					monoText(c, msg.HandoffLCDevicePathValue(targetFilename)).FontSize(12).TextColor(accentInk(t))
				} else {
					monoText(c, msg.HandoffDevicePathValue(targetFilename)).FontSize(12).TextColor(accentInk(t))
				}
			})
		}
		if m.exportedPath != "" {
			surfaceCard(c, "exported-mac-path-card").Padding(14, 16).Gap(6).Children(func() {
				ui.Text(c, msg.HandoffMacPathTitle()).Bold().FontSize(13)
				monoText(c, m.exportedPath).FontSize(12).TextColor(accentInk(t))
			})
		}

		surfaceCard(c, "verify-install-card").Padding(16, 18).Gap(10).Children(func() {
			ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(10).Children(func() {
				ui.Text(c, msg.HandoffVerifyTitle()).Bold().FontSize(15).Grow(1)
				if uiBtn(c, "verify-refresh-device", msg.HandoffVerifyCheckBtn()).Clicked() {
					m.detectDevices()
				}
			})
			if isLCInside && lcInstalled {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, phCheckCircleFill).Width(18).Height(18).TextColor(ui.Hex("#10B981"))
					ui.Text(c.Key("verify-status-text"), msg.HandoffVerifyLCDetected(valueOrUnknown(msg, lcMatch.Name), lcMatch.BundleID, valueOrUnknown(msg, lcMatch.Version))).Role(ui.RoleStatus).FontSize(12).Grow(1)
				})
			} else if isLCInside && m.lcApp != nil {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, phCheckCircleFill).Width(18).Height(18).TextColor(ui.Hex("#10B981"))
					ui.Text(c.Key("verify-status-text"), msg.HandoffVerifyLCReady(m.lcApp.BundleID)).Role(ui.RoleStatus).FontSize(12).Grow(1)
				})
			} else if installedOnDevice {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, phCheckCircleFill).Width(18).Height(18).TextColor(ui.Hex("#10B981"))
					ui.Text(c.Key("verify-status-text"), msg.HandoffVerifyMatch(valueOrUnknown(msg, installedMatch.Name), installedMatch.BundleID, valueOrUnknown(msg, installedMatch.Version))).Role(ui.RoleStatus).FontSize(12).Grow(1)
				})
			} else {
				ui.Text(c.Key("verify-status-text"), msg.HandoffVerifyNotFound(valueOrUnknown(msg, targetBundleID))).Role(ui.RoleStatus).FontSize(12).TextColor(t.TextMuted)
			}
			ui.Row(c).Gap(10).Children(func() {
				if uiBtn(c, "transfer-back", msg.NavBack()).Clicked() {
					m.goTaskSection("文件", 3)
				}
				confirmLabel := msg.HandoffUserConfirmBtn()
				if isLCInside {
					confirmLabel = msg.HandoffVerifyLCConfirmBtn()
				}
				var confirmBtn ui.Element
				if readyToConfirm {
					confirmBtn = uiPrimaryBtn(c, "handoff-user-confirm", confirmLabel)
				} else {
					confirmBtn = uiBtn(c, "handoff-user-confirm", confirmLabel)
				}
				if confirmBtn.Clicked() {
					m.userConfirmed = true
					m.goTaskSection("维护", 5)
				}
			})
		})
	}

	sidePane := func() {
		insetGroup(c, "transfer-next-steps-group", func() {
			ui.Column(c).FillWidth().Padding(16, 18).Gap(8).Children(func() {
				if isLCInside {
					ui.Text(c, msg.HandoffLCStepsTitle()).Bold().FontSize(14)
					ui.Text(c, msg.HandoffLCStep1()).FontSize(12)
					ui.Text(c, msg.HandoffLCStep2()).FontSize(12)
					ui.Text(c, msg.HandoffLCStep3(targetFilename)).FontSize(12)
				} else {
					ui.Text(c, msg.TransferNextSteps()).Bold().FontSize(14)
					ui.Text(c, msg.TransferNextStep1()).FontSize(12)
					ui.Text(c, msg.TransferNextStep2()).FontSize(12)
					ui.Text(c, msg.TransferNextStep3()).FontSize(12)
				}
			})
		})
		if isLCInside {
			insetGroup(c, "transfer-lc-advanced-group", func() {
				ui.Column(c).FillWidth().Padding(14, 16).Gap(8).Transition(heightTransition).Children(func() {
					ui.Collapsible(c.Key("lc-advanced-collapsible"), msg.LcAdvancedTitle(), &m.showLCAdvanced, func() {
						ui.Column(c).FillWidth().Gap(6).Padding(4, 0, 0, 0).Children(func() {
							ui.Text(c, msg.LcAdvancedMultiTitle()).Bold().FontSize(12)
							ui.Text(c, msg.LcAdvancedMultiDesc()).FontSize(11).TextColor(t.TextMuted)
							if uiBtn(c, "handoff-iphone-shortcuts", msg.ShortcutsTitle()).Clicked() {
								m.openHelp(helpShortcutLaunch)
							}
						})
					}).Cursor(ui.CursorPointer)
				})
			})
		}
		if uiBtn(c, "transfer-missing-file-help", msg.HelpTopicMissingFileTitle()).Clicked() {
			m.openHelp("missing")
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
		ui.Column(c).Width(248).Shrink(0).Gap(14).Children(sidePane)
	})
}

func (m *Model) maintainView(c *ui.Context, msg locales.Messages, _ bool) {
	t := c.Theme()
	m.taskHeaderAndSteps(c, msg, 5)

	if m.recoveryMode {
		ui.Column(c).FillWidth().Gap(4).Children(func() {
			ui.Text(c, msg.MaintainRecoveryTitle()).FontSize(26).Bold()
			ui.Text(c, msg.MaintainRecoverySubtitle()).TextColor(t.TextMuted)
		})
		insetGroup(c, "recovery-branches-group", func() {
			ui.Row(c).FillWidth().Padding(16, 18).Gap(14).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phCheckCircleFill).Width(20).Height(20).TextColor(ui.Hex("#10B981"))
				ui.Column(c).Grow(1).Gap(3).Children(func() {
					ui.Text(c, msg.MaintainRecoveryOpenableTitle()).Bold().FontSize(14)
					ui.Text(c, msg.MaintainRecoveryOpenableDesc()).FontSize(12).TextColor(t.TextMuted)
				})
				if uiBtn(c, "recovery-back-maintain", msg.MaintainBackToMaintain()).Clicked() {
					m.recoveryMode = false
				}
			})
			ui.Divider(c)
			m.recoveryInstallRow(c, msg)
			m.toolInstallStatusRow(c, msg)
		})
		return
	}

	if m.userConfirmed {
		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			brandLogoBadge(c, 42)
			ui.Text(c, msg.MaintainTitle()).FontSize(26).Bold()
		})
	}
	ui.Column(c).FillWidth().Gap(4).Children(func() {
		if !m.userConfirmed {
			ui.Text(c, msg.MaintainTitle()).FontSize(26).Bold()
		}
		ui.Text(c, msg.MaintainSubtitle()).TextColor(t.TextMuted)
		if m.maintainApp != "" {
			ui.Text(c, msg.MaintainTargetApp(m.maintainApp)).FontSize(12).Bold().TextColor(accentInk(t))
		}
	})

	surfaceCard(c, "maintain-steps-card").Padding(18, 20).Gap(10).Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, phRefresh).Width(20).Height(20).TextColor(accentInk(t))
			ui.Text(c, msg.MaintainStepsTitle()).Bold().FontSize(15)
		})
		if m.installRoute == "livecontainer" && m.lcPlacement != "outside" {
			ui.Row(c).FillWidth().Padding(10, 12).Gap(8).Radius(8).Background(t.Selection).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phInfo).Width(16).Height(16).TextColor(accentInk(t))
				ui.Text(c, msg.MaintainLCHint()).FontSize(12).Grow(1)
			})
		}
		ui.Text(c, msg.MaintainStep1()).FontSize(13)
		ui.Text(c, msg.MaintainStep2()).FontSize(13)
		ui.Text(c, msg.MaintainStep3()).FontSize(13)
		ui.Divider(c)
		ui.Text(c, msg.MaintainExpiryNote()).FontSize(12).TextColor(t.TextMuted)
		if uiBtn(c, "maintain-verify-profile", msg.MaintainVerifyProfile()).Clicked() {
			c.OpenURL("https://livecontainer.github.io/docs/guides/refresh-verification")
		}
	})
	ui.Row(c).Gap(10).Children(func() {
		if uiBtn(c, "maintain-recovery-btn", msg.MaintainRecoveryBtn()).Clicked() {
			m.recoveryMode = true
		}
		if uiPrimaryBtn(c, "maintain-home-btn", msg.GuideFinish()).Clicked() {
			m.section = "准备"
		}
	})
	m.shortcutsPanel(c, msg)
}

func (m *Model) recoveryInstallRow(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	m.mu.Lock()
	lc, busy := m.lcApp, m.toolInstalling
	m.mu.Unlock()
	ui.Column(c).FillWidth().Padding(16, 18).Gap(8).Children(func() {
		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, phWarningFill).Width(20).Height(20).TextColor(ui.Hex("#F59E0B"))
			ui.Text(c, msg.MaintainRecoveryExpiredTitle()).Grow(1).Bold().FontSize(14)
		})
		ui.Text(c, msg.MaintainRecoveryExpiredDesc()).FontSize(13)
		ui.Text(c, msg.MaintainRecoveryOriginalInstaller()).FontSize(12).TextColor(t.TextMuted)
		if lc != nil {
			monoText(c, msg.MaintainRecoveryTarget(lc.BundleID)).FontSize(11).TextColor(t.TextMuted)
		}
		ui.Row(c).FillWidth().Wrap().Gap(8).Children(func() {
			if m.deviceBtn(c, msg, "recover-lcss-btn", msg.MaintainRecoveryLCBtn(), true, busy || lc == nil).Clicked() && lc != nil {
				m.installEcosystemTool(installer.TargetLiveContainerLCSS, lc.BundleID)
			}
			if uiBtn(c, "recovery-open-setup", msg.ToolsOpenGuide()).Clicked() {
				c.OpenURL("https://livecontainer.github.io/docs/installation/lc_sidestore")
			}
		})
	})
}

func (m *Model) toolInstallStatusRow(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	m.mu.Lock()
	busy := m.toolInstalling
	pct := m.toolInstallPct
	stage := m.toolInstallMsg
	errMsg := m.toolInstallErr
	done := m.toolInstallDone
	m.mu.Unlock()
	if !busy && stage == "" && errMsg == "" {
		return
	}
	ui.Divider(c)
	ui.Column(c).FillWidth().Padding(10, 18).Gap(6).Children(func() {
		localizedStage := progressStageLabel(msg, stage)
		if busy || done {
			deliveryProgress(c, "tool-install-progress", localizedStage, float64(pct)/100, done).FillWidth()
		}
		if busy {
			ui.Text(c, msg.ToolInstallRunning(localizedStage, pct)).FontSize(12).TextColor(accentInk(t))
		} else if errMsg != "" {
			ui.Text(c.Key("tool-install-err"), msg.ToolInstallFailed(friendlyError(msg, errMsg))).FontSize(12).TextColor(ui.Hex("#EF4444")).
				Transition(feedbackBannerTransition)
		} else if stage != "" {
			ui.Text(c.Key("tool-install-done"), localizedStage).Role(ui.RoleStatus).FontSize(12).Bold().TextColor(successInk(t)).
				Transition(feedbackBannerTransition)
			if done {
				ui.Column(c).FillWidth().Padding(10, 12).Gap(4).Radius(8).Background(t.Selection).Children(func() {
					ui.Text(c, msg.PostInstallChecklistTitle()).Bold().FontSize(12)
					ui.Text(c, msg.PostInstallStepDevMode()).FontSize(11).TextColor(t.TextMuted)
					ui.Text(c, msg.PostInstallStepTrust()).FontSize(11).TextColor(t.TextMuted)
					ui.Text(c, msg.PostInstallStepRefresh()).FontSize(11).TextColor(t.TextMuted)
					ui.Text(c, msg.PostInstallStepLCSS()).FontSize(11).TextColor(t.TextMuted)
				})
			}
		}
	})
}

func (m *Model) triggerDeveloperMode() {
	if !m.hasConnectedDevice() {
		return
	}
	m.mu.Lock()
	dev := m.devices[0]
	m.devModeErr = ""
	m.devModeMsg = ""
	m.mu.Unlock()

	go func() {
		sess, err := device.DialSession(nil, dev.ID, dev.UDID)
		if err == nil {
			defer sess.Close()
			err = sess.RevealDeveloperMode()
			if err == nil {
				_ = sess.EnableDeveloperMode()
			}
		}
		curMsg := m.msg(nil)
		m.mu.Lock()
		if err != nil {
			m.devModeErr = err.Error()
		} else {
			m.devModeMsg = curMsg.DeviceDevModeRevealed()
		}
		m.mu.Unlock()
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) confirmToolInstall(target installer.ToolTarget) {
	m.mu.Lock()
	m.pendingToolInstall = target
	m.mu.Unlock()
}

func (m *Model) toolInstallConfirmModal(c *ui.Context, msg locales.Messages) {
	m.mu.Lock()
	target := m.pendingToolInstall
	embedded := m.sideStoreEmbedded
	standalone := m.sideStoreApp != nil
	m.mu.Unlock()
	if target == "" {
		return
	}

	t := c.Theme()
	var toolName, body, conflict string
	switch target {
	case installer.TargetSideStore:
		toolName = "SideStore"
		body = msg.ToolConfirmSideStoreDesc()
		if embedded {
			conflict = msg.ToolConfirmConflictEmbedded()
		}
	case installer.TargetLiveContainerLCSS:
		toolName = "LiveContainer + SideStore"
		body = msg.ToolConfirmLCSSDesc()
		if standalone {
			conflict = msg.ToolConfirmConflictStandalone()
		}
	case installer.TargetLiveContainerOnly:
		toolName = "LiveContainer"
		body = msg.ToolConfirmLCOnlyDesc()
	default:
		toolName = string(target)
	}

	open := true
	ui.Modal(c.Key("tool-confirm-modal"), &open, func() {
		ui.Column(c).Width(420).Gap(12).Children(func() {
			ui.Text(c, msg.ToolConfirmTitle(toolName)).Bold().FontSize(16)
			ui.Text(c, body).FontSize(12)
			if conflict != "" {
				ui.Row(c).FillWidth().Padding(10, 12).Gap(8).Radius(8).
					Background(t.SurfaceHover).Border(1, ui.Hex("#F59E0B")).AlignItems(ui.Start).Children(func() {
					ui.Icon(c, phWarningFill).Width(16).Height(16).TextColor(ui.Hex("#F59E0B"))
					ui.Text(c, conflict).FontSize(11).Grow(1)
				})
			}
			ui.Row(c).FillWidth().Gap(8).Justify(ui.End).Children(func() {
				if uiBtn(c, "tool-confirm-cancel", msg.LibraryCancel()).Clicked() {
					m.mu.Lock()
					m.pendingToolInstall = ""
					m.mu.Unlock()
				}
				confirmBtn := m.deviceBtn(c, msg, "tool-confirm-ok", msg.ToolConfirmInstallBtn(), true, false)
				if confirmBtn.Clicked() {
					m.mu.Lock()
					m.pendingToolInstall = ""
					m.mu.Unlock()
					m.installEcosystemTool(target, "")
				}
			})
		})
	})
	if !open {
		m.mu.Lock()
		m.pendingToolInstall = ""
		m.mu.Unlock()
	}
}

func (m *Model) recordStore() *installer.RecordStore {
	return installer.NewRecordStore(filepath.Join(localDataDir(), "installed_records.json"))
}
func (m *Model) installEcosystemTool(target installer.ToolTarget, recoveryBundleID string) {
	msg := m.msg(nil)
	m.mu.Lock()
	if len(m.devices) == 0 || m.deviceErr != "" {
		m.toolInstallErr = msg.ToolInstallNeedDevice()
		m.mu.Unlock()
		return
	}
	if m.services.Accounts == nil || !m.services.Accounts.Developer().SignedIn() {
		m.toolInstallErr = msg.ToolInstallNeedLogin()
		m.mu.Unlock()
		source := "device"
		if recoveryBundleID != "" {
			source = "task"
		}
		m.navigateToAccountForLogin(source, m.section, m.taskStage)
		return
	}
	if recoveryBundleID != "" && (m.lcApp == nil || m.lcApp.BundleID != recoveryBundleID) {
		m.toolInstallErr = msg.MaintainRecoveryOriginalInstaller()
		m.mu.Unlock()
		return
	}
	if m.toolInstalling {
		m.mu.Unlock()
		return
	}
	dev := m.devices[0]
	info := m.deviceInfo
	m.toolInstalling = true
	m.toolInstallPct = 5
	m.toolInstallMsg = string(target)
	m.toolInstallErr = ""
	m.toolInstallDone = false
	m.mu.Unlock()
	m.addLog("tool install started: " + string(target))
	if m.win != nil {
		m.win.Invalidate()
	}

	go func() {
		res, err := installer.InstallDirect(context.Background(), installer.InstallRequest{
			Target:           target,
			RecoveryBundleID: recoveryBundleID,
			CacheDir:         filepath.Join(localDataDir(), "downloads"),
			Device:           dev,
			DeviceInfo:       info,
			Accounts:         m.services.Accounts,
			OnMaxCerts:       m.promptMaxCerts,
			RecordStore:      m.recordStore(),
			OnProgress: func(pct int, stage string) {
				m.mu.Lock()
				m.toolInstallPct = pct
				m.toolInstallMsg = stage
				m.mu.Unlock()
				m.addLog(fmt.Sprintf("tool install %d%%: %s", pct, stage))
				if m.win != nil {
					mygo.RunOnMain(func() { m.win.Invalidate() })
				}
			},
		})
		curMsg := m.msg(nil)
		m.mu.Lock()
		m.toolInstalling = false
		if errors.Is(err, signing.ErrRecoveryBundleIDMismatch) {
			m.toolInstallErr = curMsg.MaintainRecoveryOriginalInstaller()
		} else if err != nil {
			m.toolInstallErr = err.Error()
		} else {
			m.toolInstallPct = 100
			m.toolInstallDone = true
			m.toolInstallMsg = curMsg.ToolInstallSucceeded(res.BundleID)
			if recoveryBundleID != "" {
				m.toolInstallMsg += "\n" + curMsg.MaintainRecoveryAfterInstall()
			}
			if res.PairingWarning != "" {
				m.toolInstallMsg += " (" + friendlyError(curMsg, res.PairingWarning) + ")"
			}
		}
		m.mu.Unlock()
		if err != nil {
			m.addLog("tool install failed: " + err.Error())
		} else {
			m.addLog("tool install succeeded: " + res.BundleID)
			m.detectDevices()
		}
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) renewAppProfile(rec installer.Record) {
	if len(m.devices) == 0 || m.deviceErr != "" {
		return
	}
	dev := m.devices[0]
	m.mu.Lock()
	m.toolInstallPct = 10
	m.toolInstallMsg = "certificate"
	m.toolInstalling = true
	m.toolInstallErr = ""
	m.toolInstallDone = false
	m.mu.Unlock()
	if m.win != nil {
		m.win.Invalidate()
	}

	go func() {
		res, err := installer.RefreshProfiles(context.Background(), dev, nil, m.services.Accounts, rec, m.recordStore(), func(pct int, stage string) {
			m.mu.Lock()
			m.toolInstallPct = pct
			m.toolInstallMsg = stage
			m.mu.Unlock()
			if m.win != nil {
				mygo.RunOnMain(func() { m.win.Invalidate() })
			}
		})
		curMsg := m.msg(nil)
		m.mu.Lock()
		m.toolInstalling = false
		if err != nil {
			m.toolInstallErr = err.Error()
		} else {
			m.toolInstallPct = 100
			m.toolInstallDone = true
			m.toolInstallMsg = curMsg.ToolInstallSucceeded(res.InstalledID)
		}
		m.mu.Unlock()
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) placePairingToAll() {
	msg := m.msg(nil)
	if !m.hasConnectedDevice() {
		m.mu.Lock()
		m.pairingErr = msg.ToolInstallNeedDevice()
		m.mu.Unlock()
		return
	}
	m.mu.Lock()
	if m.pairingBusy {
		m.mu.Unlock()
		return
	}
	dev := m.devices[0]
	info := m.deviceInfo
	apps := append([]device.InstalledApp(nil), m.deviceApps...)
	m.pairingBusy = true
	m.pairingErr = ""
	m.pairingMsg = ""
	m.mu.Unlock()

	go func() {
		targets := device.DetectPairingTargets(apps)
		var names []string
		var lastErr error
		if len(targets) == 0 {
			lastErr = errors.New("no compatible pairing app detected on device")
		} else {
			var storage = m.services.Accounts.Storage()
			for _, tgt := range targets {
				if err := installer.PlacePairingToTarget(nil, dev, info, storage, tgt); err != nil {
					lastErr = err
				} else {
					names = append(names, tgt.Name)
				}
			}
		}
		curMsg := m.msg(nil)
		m.mu.Lock()
		m.pairingBusy = false
		if len(names) > 0 {
			m.pairingMsg = curMsg.PairingWriteDone(strings.Join(names, ", "))
			if lastErr != nil {
				m.pairingMsg += " (" + friendlyError(curMsg, lastErr.Error()) + ")"
			}
		} else if lastErr != nil {
			m.pairingErr = friendlyError(curMsg, lastErr.Error())
		}
		m.mu.Unlock()
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) exportPairingToFile() {
	if m.win == nil || !m.hasConnectedDevice() {
		return
	}
	m.mu.Lock()
	dev := m.devices[0]
	info := m.deviceInfo
	m.mu.Unlock()
	win := m.win
	title := m.msg(nil).PairingExportBtn()

	go func() {
		raw, err := installer.ExportPairingBytes(nil, dev, info, m.services.Accounts.Storage())
		if err != nil && len(raw) == 0 {
			m.mu.Lock()
			m.pairingErr = err.Error()
			m.mu.Unlock()
			mygo.RunOnMain(func() { win.Invalidate() })
			return
		}
		outPath, saveErr := mygo.Dialog.Save(mygo.SaveDialogOptions{
			Parent:      win,
			Title:       title,
			DefaultPath: "pairingFile.plist",
			Filters:     []mygo.FileFilter{{Name: "Pairing File", Extensions: []string{"plist", "mobiledevicepairing"}}},
		})
		if saveErr != nil || outPath == "" {
			return
		}
		if writeErr := os.WriteFile(outPath, raw, 0o600); writeErr != nil {
			m.mu.Lock()
			m.pairingErr = writeErr.Error()
			m.mu.Unlock()
		} else {
			m.mu.Lock()
			m.pairingMsg = m.msg(nil).PairingWriteDone(filepath.Base(outPath))
			m.mu.Unlock()
		}
		mygo.RunOnMain(func() { win.Invalidate() })
	}()
}

func (m *Model) directInstallSelected() {
	msg := m.msg(nil)
	if !m.hasConnectedDevice() {
		m.mu.Lock()
		m.directErr = msg.ToolInstallNeedDevice()
		m.mu.Unlock()
		return
	}
	if m.services.Accounts == nil || !m.services.Accounts.Developer().SignedIn() {
		m.mu.Lock()
		m.directErr = msg.ToolInstallNeedLogin()
		m.mu.Unlock()
		m.navigateToAccountForLogin("task", m.section, m.taskStage)
		return
	}
	file, ok := m.selectedArchive()
	if !ok || file.err != "" {
		return
	}
	targetIPA := m.effectiveArchivePath(file)
	if prepared, prepErr := m.ensurePreparedArchivePath(file); prepErr == nil && prepared != "" {
		targetIPA = prepared
	}
	m.mu.Lock()
	if m.directInstallOn {
		m.mu.Unlock()
		return
	}
	dev := m.devices[0]
	info := m.deviceInfo
	m.directInstallOn = true
	m.directPct = 5
	m.directStage = "preparing"
	m.directErr = ""
	m.directDoneMsg = ""
	m.mu.Unlock()

	go func() {
		res, err := installer.InstallDirect(context.Background(), installer.InstallRequest{
			Target:         installer.TargetCustomIPA,
			LocalIPAPath:   targetIPA,
			SkipExtensions: m.skipExtensionsFor == file.path,
			Device:         dev,
			DeviceInfo:     info,
			Accounts:       m.services.Accounts,
			RecordStore:    m.recordStore(),
			OnMaxCerts:     m.promptMaxCerts,
			OnProgress: func(pct int, stage string) {
				m.mu.Lock()
				m.directPct = pct
				m.directStage = stage
				m.mu.Unlock()
				if m.win != nil {
					mygo.RunOnMain(func() { m.win.Invalidate() })
				}
			},
		})
		curMsg := m.msg(nil)
		m.mu.Lock()
		m.directInstallOn = false
		if err != nil {
			m.directErr = err.Error()
		} else {
			m.directPct = 100
			m.directDoneMsg = curMsg.ToolInstallSucceeded(res.BundleID)
		}
		m.mu.Unlock()
		if err == nil {
			m.detectDevices()
		}
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) directInstallStoreIPA(ipaPath, bundleID string) {
	msg := m.msg(nil)
	if !m.hasConnectedDevice() {
		m.mu.Lock()
		m.directErr = msg.ToolInstallNeedDevice()
		m.mu.Unlock()
		return
	}
	m.mu.Lock()
	if m.directInstallOn {
		m.mu.Unlock()
		return
	}
	dev := m.devices[0]
	m.directInstallOn = true
	m.directPct = 5
	m.directStage = "usb_install"
	m.directErr = ""
	m.directDoneMsg = ""
	m.mu.Unlock()

	go func() {
		err := installer.InstallStoreIPA(context.Background(), ipaPath, dev, nil, func(pct int, stage string) {
			m.mu.Lock()
			m.directPct = pct
			m.directStage = stage
			m.mu.Unlock()
			if m.win != nil {
				mygo.RunOnMain(func() { m.win.Invalidate() })
			}
		})
		curMsg := m.msg(nil)
		m.mu.Lock()
		m.directInstallOn = false
		if err != nil {
			m.directErr = err.Error()
		} else {
			m.directPct = 100
			if bundleID == "" {
				bundleID = filepath.Base(ipaPath)
			}
			m.directDoneMsg = curMsg.StoreInstallDone(bundleID)
		}
		m.mu.Unlock()
		if err == nil {
			m.detectDevices()
		}
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}
