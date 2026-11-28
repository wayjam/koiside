<div align="center">

<img src="docs/images/readme-brand.webp" alt="KoiSide — Sideloading, made simple." width="100%" />

**Prepare, sign, and sideload your own iPhone apps with guidance along the way.**

[![Platform](https://img.shields.io/badge/macOS_14%2B-Apple_Silicon_%26_Intel-black?logo=apple)](https://github.com/wayjam/koiside/releases)
[![Go](https://img.shields.io/badge/Go-1.27.4%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)

[Download](https://github.com/wayjam/koiside/releases) · [Build from source](#build-from-source) · [Report an issue](https://github.com/wayjam/koiside/issues)

</div>

## Why KoiSide?

Start with an IPA and follow a guided sideloading workflow. KoiSide helps you inspect the file, choose an installation route, make optional changes, and find the next step on your iPhone. Return later to continue a task or review refresh instructions.

Built in Go with [mygo](https://github.com/egoist/mygo), KoiSide uses GPU-rendered native UI with light and dark appearances. Device communication and IPA preparation run within the app, with macOS system services handling the connection to your iPhone.

## Features

- **Inspect and prepare IPA files.** Check metadata, architectures, FairPlay encryption, provisioning information, extensions, and Watch components. Preview display-name or Bundle ID changes and export a new copy while preserving the input file. Inspection and export work offline.
- **Choose how to sideload.** Hand off an IPA over USB to SideStore or LiveContainer where file sharing is available, or use desktop signing and USB installation. Free Personal Team accounts are supported for development signing.
- **Set up your device.** Check connected iPhones and installed apps, prepare pairing files, and follow setup instructions for SideStore, LocalDevVPN, and LiveContainer.
- **Set up iPhone shortcuts.** Export a signed shortcut for SideStore refresh or to launch a specific LiveContainer app from the Home Screen.
- **Manage Apple accounts.** Use a shared account interface for App Store and developer services, with service-specific sessions and signing credentials. App Store search and downloads depend on Apple's services and account region.
- **Use KoiSide in your language.** Switch between Simplified Chinese, English, Russian, and Japanese.
- **Use the CLI or MCP server.** Inspect files, query devices, and automate supported operations from the same executable.

## Screenshots

| Device & pairing | Sideload help & tools |
| --- | --- |
| <img src="docs/screenshots/device.webp" alt="Connected iPhone, sideloading tools, and pairing options" width="400" /> | <img src="docs/screenshots/help.webp" alt="Sideloading routes and contextual setup guides" width="400" /> |

## Install

Requires **macOS 14 or later on Apple Silicon or Intel**.

1. Download the macOS `arm64` (Apple Silicon) or `amd64` (Intel) build from [Releases](https://github.com/wayjam/koiside/releases).
2. Extract the archive or open the disk image and move **KoiSide.app** to **Applications**.
3. Open KoiSide and select an IPA. Connect and unlock your iPhone when prompted, then confirm **Trust** on the device.

For an ad-hoc signed build that macOS blocks, review the app's source and follow Apple's instructions for opening an app from an unidentified developer. [Apple's opening instructions](https://support.apple.com/en-us/102445)

### Sideloading requirements

- Use an IPA suitable for your chosen installation route. App Store downloads can retain FairPlay encryption and require a different, sideloadable build for re-signing.
- Free Personal Team provisioning profiles expire after seven days. Refresh before expiry through your chosen workflow. KoiSide's guides explain when to use SideStore, LocalDevVPN, Wi-Fi, and iOS Developer Mode.
- USB file transfer and installation have separate results. After a SideStore handoff, complete the installation on your iPhone. LiveContainer runs imported apps inside its container, with compatibility depending on the app and configuration.

### Shortcuts and expired LiveContainer installs

1. Open **Sideload Help → iPhone Shortcuts** and choose the refresh or Home Screen guide. For refresh, connect and unlock the iPhone so KoiSide can identify the installed SideStore or LiveContainer + SideStore edition.
2. For a Home Screen shortcut, choose a detected app. To target a specific data container or an app outside the list, copy its launch URL from LiveContainer and paste it into KoiSide.
3. After exporting, click **Next**. Use **AirDrop** to choose the iPhone or **Show in Finder** to locate the file. Open the file on the iPhone and add it to Shortcuts. The final step shows how to test refresh, set up an optional daily automation, or add an app to the Home Screen.

Connect to Wi-Fi and LocalDevVPN before running the refresh shortcut. LiveContainer + SideStore requires the **LiveProcess** extension for its refresh action. To schedule refreshes, add **Set VPN** before the refresh action, select your LocalDevVPN profile, and create a daily **Time of Day** personal automation that runs the shortcut. Check **My Apps** after the first run. If the displayed days and iOS disagree, verify the profile installed on the phone. [Combined edition setup](https://livecontainer.github.io/docs/installation/lc_sidestore#auto-refresh-shortcut) · [Profile verification](https://livecontainer.github.io/docs/guides/refresh-verification)

If iOS says LiveContainer is no longer available after expiry, keep the existing app on the phone. Open **Sideload Help → App expiring soon or refresh failed** and choose **Refresh and recover expired apps** in the first step. Use **Recover LiveContainer + SideStore** with the original Apple Account and developer team. KoiSide checks the installed Bundle ID before updating it over USB. If the original installer used a different Bundle ID, use that installer and its original signing settings. After LiveContainer opens, connect LocalDevVPN and refresh in the built-in SideStore. [LiveContainer + SideStore setup](https://livecontainer.github.io/docs/installation/lc_sidestore#setup-after-installing)

## Build from source

Install **Go 1.27.4 or later**, as specified in [go.mod](go.mod).

```sh
git clone https://github.com/wayjam/koiside.git
cd koiside

# Run the desktop app
go run ./cmd/koiside

# Build the Apple Silicon or Intel app bundle
go tool mygo build -platform darwin/arm64 -skip-dmg
# or for Intel Mac:
# go tool mygo build -platform darwin/amd64 -skip-dmg

# Open the built application
open build/darwin-arm64/KoiSide.app
```

Omit `-skip-dmg` to also produce a disk image.

### CLI and MCP

The bundled executable is available at `/Applications/KoiSide.app/Contents/MacOS/KoiSide`. From a source checkout, run the following commands.

```sh
# Inspect an IPA
go run ./cmd/koiside ipa inspect /path/to/app.ipa --json

# Query a connected iPhone
go run ./cmd/koiside device status --json

# Start the MCP stdio server
go run ./cmd/koiside mcp
```

KoiSide stores Apple account sessions, developer keys, and pairing material in macOS Keychain; it does not fall back to plaintext files. The MCP server uses local stdio and does not open a network listener. A configured MCP client can still invoke KoiSide tools with the current user's access, including reading device/account details, installing apps, deleting files in supported app containers, and placing pairing credentials. Only connect trusted clients, review requested actions, and do not export or share pairing files.

## Development

```sh
go tool revive -config revive.toml ./...
go vet ./...
go vet -tags e2e ./...
go test -count=1 ./...
```

The macOS Keychain round-trip test uses a temporary keychain and deletes it during cleanup.

## Acknowledgments

- [mygo](https://github.com/egoist/mygo) provides the native GPU-rendered Go UI framework.
- [SideStore](https://sidestore.io/) provides on-device sideloading and refresh workflows.
- [LiveContainer](https://github.com/LiveContainer/LiveContainer) provides an on-device app container runtime.
- [Phosphor Icons](https://phosphoricons.com/) provides the interface icons.

## License

KoiSide is licensed under the [MIT License](LICENSE). Attribution and license information for the included Phosphor icon assets is in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Go dependencies are declared in `go.mod` and are not vendored.
