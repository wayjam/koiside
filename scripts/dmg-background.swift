// Deterministic Retina artwork for the Finder installer window.
// Run: swift scripts/dmg-background.swift build/dmg-background.png
import AppKit

let width = 640
let height = 400
let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: width * 2,
    pixelsHigh: height * 2, bitsPerSample: 8, samplesPerPixel: 4,
    hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
    bytesPerRow: 0, bitsPerPixel: 0)!
bitmap.size = NSSize(width: width, height: height)
let context = NSGraphicsContext(bitmapImageRep: bitmap)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = context

func color(_ hex: Int) -> NSColor {
    NSColor(srgbRed: CGFloat((hex >> 16) & 255) / 255,
        green: CGFloat((hex >> 8) & 255) / 255,
        blue: CGFloat(hex & 255) / 255, alpha: 1)
}
func text(_ value: String, y: CGFloat, size: CGFloat, weight: NSFont.Weight, ink: Int) {
    let style = NSMutableParagraphStyle()
    style.alignment = .center
    (value as NSString).draw(in: NSRect(x: 24, y: y, width: 592, height: size * 1.7),
        withAttributes: [.font: NSFont.systemFont(ofSize: size, weight: weight),
            .foregroundColor: color(ink), .paragraphStyle: style])
}
color(0xF3F5F8).setFill()
NSRect(x: 0, y: 0, width: width, height: height).fill()
text("KoiSide", y: 326, size: 28, weight: .semibold, ink: 0x172334)
text("Drag KoiSide to Applications to install", y: 70, size: 16, weight: .medium, ink: 0x506176)

let arrow = NSBezierPath()
arrow.move(to: NSPoint(x: 292, y: 220))
arrow.line(to: NSPoint(x: 348, y: 220))
arrow.move(to: NSPoint(x: 336, y: 232))
arrow.line(to: NSPoint(x: 348, y: 220))
arrow.line(to: NSPoint(x: 336, y: 208))
arrow.lineWidth = 3
arrow.lineCapStyle = .round
arrow.lineJoinStyle = .round
color(0x1769D2).setStroke()
arrow.stroke()
NSGraphicsContext.restoreGraphicsState()
try bitmap.representation(using: .png, properties: [:])!.write(
    to: URL(fileURLWithPath: CommandLine.arguments[1]))
