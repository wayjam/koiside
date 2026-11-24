---
name: KoiSide
description: A clear, trustworthy desktop assistant for iPhone sideloading and IPA preparation, with a macOS-first experience and portable native UI.
---

# Design Guidelines

## Overview

KoiSide helps people install apps they prepare themselves on a non-jailbroken iPhone. Its visual direction is a **quiet, clear desktop workspace**. Home and setup flows focus on the next action; technical details appear when needed. Clear states, familiar native controls, and readable blue accents establish the product's identity.

Keep **preparation (inspection, modification, and export)**, **file transfer**, **user-confirmed import**, **app detection on the device**, and **SideStore refresh** distinct. Show a completed result only when supported by evidence. Importing, inspecting, and exporting an IPA remain available offline without a connected phone.

Prioritize the macOS experience with `TitleBarHiddenInset` and `VibrancySidebar`. Keep core assets and UI portable through embedded Phosphor SVG icons, semantic system fonts, native MyGo rendering, and localized strings. Avoid platform-exclusive icon libraries and hard-coded platform font names. Use the standard `Surface` background when vibrancy is unavailable.

## Colors

**The Blue Accent Rule.** Blue is the primary interaction color. Do not introduce a purple theme. The brand mark uses blue curves and an orange-and-white koi; its gradients belong to the brand artwork.

Calibrate light and dark appearances independently. Separate **solid control fills** from **text and icon accents**. Normal text must meet WCAG AA contrast of at least 4.5:1 against its actual background; large text and meaningful graphical elements require at least 3:1. Verify composed colors, gradients, and state combinations rather than assuming a token is accessible everywhere.

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| `Background` | `#F3F5F8` | `#111419` | Main workspace canvas |
| `Surface` | `#FFFFFF` | `#1A1F27` | Cards, grouped containers, and control surfaces |
| `SurfaceHover` / `SurfacePressed` | `#F1F5F9` / `#E2E8F0` | `#222833` / `#2A3240` | Hover and pressed states |
| `Border` | `#E2E8F0` | `#2A313D` | 1px dividers and container outlines |
| `Selection` | `#E8F1FD` | `#1C2F4D` | Selected rows and change previews |
| `Accent` | `#1769D2` | `#2563EB` | Primary buttons, progress fills, enabled switches, and active step badges; pair with white text |
| `AccentInk` | `#1769D2` | `#64A8FF` | Accent text, icons, status summaries, and labels on surfaces or selections |
| `Text` / `TextMuted` | `#0F172A` / `#64748B` | `#F3F4F6` / `#94A3B8` | Primary and secondary text |

- **Small warm accents:** The About area and maintenance entry points after user-confirmed installation may use a subtle gold-orange surface alongside the koi mark. Start with `#FFB85C` at 10% opacity in light mode and `#FFD28A` at 8% in dark mode. Keep primary actions, navigation, and progress blue. Status colors retain their semantic meaning.
- **Semantic states:** Success uses `#10B981`, warning `#F59E0B`, and error `#EF4444` as starting colors. Pair every state with text or a recognizable symbol, and adjust text shades for contrast. Show “Unknown” when evidence is unavailable; never imply success with green.
- **Primary button gradients:** A restrained Oklab linear gradient is allowed: `#1F73DC` to `#1769D2` in light mode, and `#2563EB` to `#1D4ED8` in dark mode. A subtle 1px top inset highlight may add definition. Keep white text readable across the entire gradient.

## Typography

- **System sans-serif:** Follow the system UI font stack. Support runtime switching between Simplified Chinese (`zh-Hans`), English (`en`), Russian (`ru`), and Japanese (`ja`). Use 26–28pt bold page titles, 15–18pt bold card headings, 13–14pt body text and labels, and 11–12pt supporting text.
- **Technical text:** Use `Font("monospace")` and `FontFeatures("tnum")` for bundle identifiers, SHA-256 hashes, architectures such as `arm64`, versions, file sizes, paths, and redacted diagnostic logs. Keep ordinary explanations in the body font.
- **Localization:** Leave room for translated labels and controls. Navigation, groups, and actions must remain readable without clipping or overflow when switching languages.

## Layout and Components

**The Next Step Rule.** Each screen emphasizes one primary task. Keep component trees, implementation flags, and detailed signing errors behind progressive disclosure.

### Window sizes

- **Wide windows (720pt and above):** Use a resizable left sidebar, initially 216pt wide, and a scrollable workspace. Support dragging the sidebar divider and double-clicking to reset its width. The IPA library uses a list beside a summary and handoff panel. The change review uses an editing form beside a before-and-after comparison.
- **Narrow windows (below 720pt):** Replace the sidebar with compact horizontal navigation. Switch the IPA library between list and detail views with a visible Back action. Stack the editing form and comparison vertically. Preserve selection and unsaved edits across resizing.

### Grouping

- Use `surfaceCard` for primary focus areas such as the home device summary, IPA summary, and change preview. Use 14pt corners with one border or a subtle shadow; avoid combining borders with heavy shadows.
- Use `insetGroup` for recent files, setup tools, installed apps, and settings groups. Use a 12pt rounded container with 1px dividers between rows. Avoid a separate card for every row or nested cards.

### Native controls

- Use `ui.Segmented` for mutually exclusive settings such as appearance and language.
- Use `ui.Collapsible` for advanced IPA details and redacted diagnostic logs.
- Use `ui.Switch` for component removal options.
- Use native window controls. Do not draw imitation macOS traffic-light buttons.

## Brand, Icons, and Media

### KoiSide mark

The mark combines an open blue arc, a flowing S-shaped body, and an orange-and-white koi facing toward the upper right, with its tail sweeping left. The open arc and flowing curves suggest movement into and through the sideloading workflow. Keep the symbol free of text; place the product name separately when needed.

Preserve proportions, orientation, markings, and the complete silhouette. Do not crop the tail or outer arc, stretch the mark, add a phone or container, or apply decorative outlines. Blue and orange gradients are part of the artwork; they do not redefine interaction or warning colors.

Allow clear space of at least 12% of the visible mark's height around the symbol. Measure the visible silhouette rather than counting transparent padding twice. When placing the name beside or below the mark, keep at least the same separation and use the system sans-serif font.

The following are normalized brand targets, not a claim that every raster pixel matches an exact value:

| Color | Target | Use |
| --- | --- | --- |
| Brand blue | `#3567F2` | Outer arc and main blue surfaces |
| Pale blue | `#A7BFF1` | Light transitions within the arc and body |
| Koi orange | `#FF7A2B` | Head markings and fins |
| Light gold | `#FFD28A` | Light transitions within orange fins |

Use the transparent brand mark inside the app. Export the macOS application icon separately with its own pale rounded-square tile and optical padding. The current `.icns` has a fixed light appearance in both system themes; do not describe it as an automatically switching dark icon. Assess the mark on light and dark surfaces independently rather than inverting the artwork.

Use a 1024 × 1024px application icon export and the required macOS size variants. Check the silhouette, edge quality, and optical size in Finder and the Dock. Inspect small sizes individually; a detailed full-size mark is not automatically legible at 16–32px. Do not claim that a raster asset is an editable vector master.

### Interface icons

Use embedded, cross-platform **Phosphor Icons (`ph`)** SVG assets:

- Pair `regular` icons for unselected navigation with `fill` icons for selected navigation.
- Use `duotone` icons for empty states, disconnected devices, inspection progress, FairPlay blocking, and setup guidance.
- Keep action and status icons within the same family and use consistent visual weights.

### App artwork

Extract the main app's icon from the IPA, including Apple `CgBI` PNG decoding, for recent files, the IPA list, and change comparisons. Fall back to a Phosphor badge when no usable icon is available. App artwork helps recognition; it does not establish provenance, signature validity, or authenticity.

## Elevation, Motion, and Interaction

- **Restrained depth:** Dark surfaces may use a fine top inset highlight, such as white at 6% opacity, to distinguish layers. A low-opacity radial light in the home screen's upper corner is acceptable. Keep decorative illustrations out of the primary task area.
- **Purposeful motion:** Use 140ms color transitions on hover, `Snappy` expansion for collapsible details, insertion and removal transitions for rows, a subtle pressed scale of `0.988`, a 2pt arrow nudge on hover, and Oklab transitions for status indicators. Respect the system's Reduce Motion preference.
- **Background sign-in:** Replace the submitted form with an indeterminate spinner and a status label. Keep navigation available. Show the verification action in the account card or in the workspace footer on other pages, and open the dialog when the user chooses to enter their code. Restore the form with an error after a failed attempt. In Reduce Motion, keep the status label visible without the spinner.
- **Session recovery:** At startup, label saved-session recovery separately from sign-in. Keep navigation and App Store search available while account sections show the recovery status.

## Workflow and State Requirements

1. **FairPlay blocking:** When inspection finds `cryptid 1`, show a blocking explanation directly in the summary. Disable “Transfer to SideStore” and modification/export actions. Keep “Choose another IPA” and inspection details available.
2. **Export to handoff:** After exporting a modified IPA, offer “Transfer now to SideStore” in place. Keep the original input file read-only.
3. **USB and LocalDevVPN:** In the SideStore file-sharing workflow, USB writes the IPA into SideStore's document container; it does not provide the on-device installation service connection. Guidance must remind users to enable LocalDevVPN before installation or refresh, including when the phone is connected to the computer.
4. **Tool detection:** Show SideStore, LocalDevVPN, and LiveContainer as “Detected” with a version, or “Not detected,” based on device evidence. Treat running and connection states as unknown unless independently verified.
5. **Resumable guidance and privacy:** Let users skip setup or connect a device later. Skipping does not mark a step complete or erase data. Guidance remains available for later installation sessions. Redact logs by default and keep them local.

## macOS Distribution

The DMG should present KoiSide on the left and the Applications shortcut on the right, joined by a simple blue arrow. Use the English instruction **“Drag KoiSide to Applications to install”**. Keep the installer artwork uncluttered and its window dimensions and icon positions consistent.

The installation background is a fixed light surface; it does not automatically follow the system theme. Keep license and third-party notices inside the app bundle rather than exposing loose documents in the DMG root. Include these resources before signing the app.

## Public References

- [Apple Human Interface Guidelines: Sidebars](https://developer.apple.com/design/human-interface-guidelines/sidebars)
- [Apple Human Interface Guidelines: Dark Mode](https://developer.apple.com/design/human-interface-guidelines/dark-mode)
- [Phosphor Icons](https://phosphoricons.com)
