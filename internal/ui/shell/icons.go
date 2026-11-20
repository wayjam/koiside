package shell

import (
	"embed"

	"github.com/egoist/mygo/ui"
)

//go:embed assets/icons/*.svg
var iconFS embed.FS

//go:embed assets/brand/logo.png
var brandLogoPNG []byte

var brandLogo = mustBrandLogo()

func mustBrandLogo() *ui.Bitmap {
	bitmap, err := ui.DecodeBitmap(brandLogoPNG)
	if err != nil {
		panic("shell: invalid brand logo: " + err.Error())
	}
	return bitmap
}

func mustIcon(name string) *ui.SVG {
	data, err := iconFS.ReadFile("assets/icons/" + name + ".svg")
	if err != nil {
		panic("shell: missing icon " + name + ": " + err.Error())
	}
	return ui.MustParseSVG(data)
}

var (
	// Navigation (regular + fill pairs from Phosphor)
	phHouse       = mustIcon("house")
	phHouseFill   = mustIcon("house-fill")
	phStack       = mustIcon("stack")
	phStackFill   = mustIcon("stack-fill")
	phDevice      = mustIcon("device-mobile")
	phDeviceFill  = mustIcon("device-mobile-fill")
	phWrench      = mustIcon("wrench")
	phWrenchFill  = mustIcon("wrench-fill")
	phCompass     = mustIcon("compass")
	phCompassFill = mustIcon("compass-fill")
	phAccount     = mustIcon("user-circle")
	phAccountFill = mustIcon("user-circle-fill")
	phGear        = mustIcon("gear")
	phGearFill    = mustIcon("gear-fill")
	phKey         = mustIcon("key")
	// Actions & directional
	phImport     = mustIcon("download-simple-bold")
	phExport     = mustIcon("upload-simple-bold")
	phCaretRight = mustIcon("caret-right")
	phCaretDown  = mustIcon("caret-down")
	phCaretLeft  = mustIcon("caret-left")
	phArrowRight = mustIcon("arrow-right")
	phRefresh    = mustIcon("arrows-clockwise")
	phSearch     = mustIcon("magnifying-glass")

	// Files & folders
	phFolderFill  = mustIcon("folder-fill")
	phFileArchive = mustIcon("file-archive")
	phFileText    = mustIcon("file-text")

	// Semantic & settings
	phUSB             = mustIcon("usb")
	phFolderOpen      = mustIcon("folder-open")
	phShieldCheck     = mustIcon("shield-check")
	phGlobe           = mustIcon("globe")
	phPalette         = mustIcon("palette")
	phQuestion        = mustIcon("question")
	phCheckCircleFill = mustIcon("check-circle-fill")
	phWarningFill     = mustIcon("warning-fill")
	phInfo            = mustIcon("info")
	phXCircleFill     = mustIcon("x-circle-fill")

	// App & tool glyphs
	phLightningFill = mustIcon("lightning-fill")
	phShieldFill    = mustIcon("shield-check-fill")
	phCubeFill      = mustIcon("cube-fill")

	// Duotone illustrations for states & onboarding
	phDeviceDuotone          = mustIcon("device-mobile-duotone")
	phDeviceSlashDuotone     = mustIcon("device-mobile-slash-duotone")
	phPackageDuotone         = mustIcon("package-duotone")
	phMagnifyingGlassDuotone = mustIcon("magnifying-glass-duotone")
	phLockKeyDuotone         = mustIcon("lock-key-duotone")
	phPaperPlaneTiltDuotone  = mustIcon("paper-plane-tilt-duotone")

	phoneBadgeSVG = ui.MustParseSVG([]byte(`<svg viewBox="0 0 36 60" fill="none">
		<rect x="1.5" y="1.5" width="33" height="57" rx="8.5" fill="#181C24" stroke="#475569" stroke-width="1.5"/>
		<rect x="4" y="4" width="28" height="52" rx="6" fill="url(#phoneScreen)"/>
		<rect x="13" y="6" width="10" height="2.6" rx="1.3" fill="#0F172A"/>
		<rect x="9" y="18" width="18" height="4" rx="2" fill="#FFFFFF" fill-opacity="0.32"/>
		<rect x="12" y="25" width="12" height="3" rx="1.5" fill="#FFFFFF" fill-opacity="0.20"/>
		<defs>
			<linearGradient id="phoneScreen" x1="4" y1="4" x2="32" y2="56" gradientUnits="userSpaceOnUse">
				<stop stop-color="#60A5FA"/>
				<stop offset="0.55" stop-color="#2563EB"/>
				<stop offset="1" stop-color="#1E40AF"/>
			</linearGradient>
		</defs>
	</svg>`))
)
