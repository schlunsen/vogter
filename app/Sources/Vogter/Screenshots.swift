import AppKit
import SwiftUI

/// `Vogter --render-screenshots <dir>`: draws the app's real views, filled with `Demo`
/// data, into PNGs for the README. Needs no daemon and no Screen Recording permission:
/// each view is laid out in an offscreen window and drawn with `cacheDisplay`, which
/// (unlike `ImageRenderer`) also draws AppKit-backed controls such as `List` and `Form`.
/// The final framing (rounded corners, shadow, the combined hero image) uses `ImageRenderer`.
///
/// One exception: the system draws the TabView's selected tab with a material that
/// offscreen drawing can't capture, so the main window uses `ScreenshotWindow`, a
/// replica of the tab strip around the real tab views.
@MainActor
enum Screenshots {
    static let windowSize = CGSize(width: 1000, height: 640)
    static let tabs: [(id: String, title: String)] = [
        ("findings", "Findings"), ("activity", "Activity"), ("trusted", "Trusted"), ("status", "Status"),
    ]

    static func render(to dir: URL) -> Bool {
        _ = NSApplication.shared
        NSApp.setActivationPolicy(.prohibited)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        } catch {
            fail("cannot create \(dir.path): \(error)")
            return false
        }
        var ok = true
        for scheme in [ColorScheme.light, .dark] {
            let suffix = scheme == .dark ? "dark" : "light"
            let menu = capture(MenuView().environment(Demo.model()), size: nil, scheme: scheme, titled: false)
            ok = save(framed(menu, scheme: scheme, cornerRadius: 12), dir, "menu-\(suffix).png") && ok

            var windows: [String: NSImage] = [:]
            for tab in tabs.map(\.id) {
                let view = ScreenshotWindow(tab: tab).environment(Demo.model())
                let image = capture(view, size: windowSize, scheme: scheme, titled: true)
                windows[tab] = image
                ok = save(framed(image, scheme: scheme, cornerRadius: 12), dir, "\(tab)-\(suffix).png") && ok
            }
            if let main = windows["activity"] {
                ok = save(hero(window: main, menu: menu, scheme: scheme), dir, "hero-\(suffix).png") && ok
            }
        }
        return ok
    }

    // MARK: Drawing

    /// Draw `view` in an offscreen window (with its title bar when `titled`) at 2x.
    private static func capture<V: View>(_ view: V, size: CGSize?, scheme: ColorScheme, titled: Bool) -> NSImage {
        // The menu bar popover has no window background of its own; give it one.
        let host = NSHostingView(rootView: view.background(Color(nsColor: .windowBackgroundColor)))
        let content = size ?? host.fittingSize
        // Far off any screen and never activated: nothing appears and focus isn't taken.
        let window = NSWindow(contentRect: NSRect(origin: CGPoint(x: -30_000, y: -30_000), size: content),
                              styleMask: titled ? [.titled, .closable, .miniaturizable, .resizable] : [.borderless],
                              backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: scheme == .dark ? .darkAqua : .aqua)
        window.title = "Vogter"
        window.isReleasedWhenClosed = false
        window.contentView = host
        window.setContentSize(content)
        window.orderFrontRegardless()
        // Let SwiftUI finish layout and the List/Form load their rows.
        RunLoop.main.run(until: Date().addingTimeInterval(0.4))
        host.layoutSubtreeIfNeeded()

        let target: NSView = titled ? (host.superview ?? host) : host
        let bounds = target.bounds
        let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(bounds.width * 2), pixelsHigh: Int(bounds.height * 2),
                                   bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                   colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        rep.size = bounds.size
        target.cacheDisplay(in: bounds, to: rep)
        window.orderOut(nil)
        window.close()
        let image = NSImage(size: bounds.size)
        image.addRepresentation(rep)
        return image
    }

    /// Rounded corners, a hairline border and a soft shadow, like a window on the desktop.
    private static func framed(_ image: NSImage, scheme: ColorScheme, cornerRadius: CGFloat) -> CGImage? {
        render(windowChrome(image, scheme: scheme, cornerRadius: cornerRadius).padding(28), scheme: scheme)
    }

    private static func windowChrome(_ image: NSImage, scheme: ColorScheme, cornerRadius: CGFloat) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        return Image(nsImage: image)
            .resizable()
            .frame(width: image.size.width, height: image.size.height)
            .clipShape(shape)
            .overlay(shape.strokeBorder(scheme == .dark ? Color.white.opacity(0.18) : Color.black.opacity(0.14), lineWidth: 1))
            .shadow(color: .black.opacity(scheme == .dark ? 0.5 : 0.22), radius: 18, y: 8)
    }

    /// The main window with the menu bar popover in front of it, top right.
    private static func hero(window: NSImage, menu: NSImage, scheme: ColorScheme) -> CGImage? {
        let scale: CGFloat = 0.9
        let menuSize = CGSize(width: menu.size.width * scale, height: menu.size.height * scale)
        let overlap: CGFloat = 150
        let view = ZStack(alignment: .topLeading) {
            windowChrome(window, scheme: scheme, cornerRadius: 12)
                .padding(.top, 50)
            windowChrome(menu, scheme: scheme, cornerRadius: 12)
                .scaleEffect(scale, anchor: .topLeading)
                .frame(width: menuSize.width, height: menuSize.height, alignment: .topLeading)
                .offset(x: window.size.width - overlap)
        }
        .frame(width: window.size.width - overlap + menuSize.width,
               height: max(window.size.height + 50, menuSize.height), alignment: .topLeading)
        .padding(28)
        return render(view, scheme: scheme)
    }

    /// Opaque, on GitHub's page colour for that appearance: the README picks the light or
    /// dark image to match, so the shadows blend in, and opaque PNGs compress far better.
    private static func render<V: View>(_ view: V, scheme: ColorScheme) -> CGImage? {
        let page = scheme == .dark ? Color(red: 13 / 255, green: 17 / 255, blue: 23 / 255) : Color.white
        let renderer = ImageRenderer(content: view.background(page).environment(\.colorScheme, scheme))
        renderer.scale = 2
        return renderer.cgImage
    }

    private static func save(_ image: CGImage?, _ dir: URL, _ name: String) -> Bool {
        let url = dir.appendingPathComponent(name)
        guard let image, let png = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:]) else {
            fail("could not render \(name)")
            return false
        }
        do {
            try png.write(to: url)
            print("wrote \(url.path) (\(image.width / 2)x\(image.height / 2) pt)")
            return true
        } catch {
            fail("cannot write \(url.path): \(error)")
            return false
        }
    }

    private static func fail(_ message: String) {
        FileHandle.standardError.write(Data("vogter screenshots: \(message)\n".utf8))
    }
}

/// `MainWindow` with its TabView chrome redrawn: the same tab titles, order and box, the
/// real tab views inside.
struct ScreenshotWindow: View {
    let tab: String

    var body: some View {
        ZStack(alignment: .top) {
            content
                .padding(.top, 17)
                .padding([.horizontal, .bottom], 2)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(0.03)))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.primary.opacity(0.1)))
                .padding(.top, 12)
            TabStrip(selected: tab)
        }
        .padding()
    }

    @ViewBuilder private var content: some View {
        switch tab {
        case "activity": ActivityTab()
        case "trusted": TrustedTab()
        case "status": StatusTab()
        default: FindingsTab()
        }
    }
}

private struct TabStrip: View {
    let selected: String
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        HStack(spacing: 2) {
            ForEach(Screenshots.tabs, id: \.id) { tab in
                Text(tab.title)
                    .font(.system(size: 13))
                    .padding(.horizontal, 14)
                    .frame(height: 20)
                    .background {
                        if tab.id == selected {
                            RoundedRectangle(cornerRadius: 6, style: .continuous)
                                .fill(scheme == .dark ? Color.white.opacity(0.22) : Color.white)
                                .shadow(color: .black.opacity(0.15), radius: 1, y: 0.5)
                        }
                    }
            }
        }
        .padding(2)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(scheme == .dark ? 0.1 : 0.06)))
    }
}
