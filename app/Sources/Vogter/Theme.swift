import AppKit
import SwiftUI

/// Vogter's soft, calm palette. Every colour adapts to light ("paper and sage") and
/// dark ("ink and dusk") appearance; views use these instead of system colours.
enum Theme {
    // MARK: Surfaces

    /// Warm off-white paper / deep charcoal-blue ink.
    static let paper = Color(light: 0xF6F3EC, dark: 0x161B22)
    /// Two ends of the very low-contrast background wash.
    static let washStart = Color(light: 0xEEF2EA, dark: 0x17222A)
    static let washEnd = Color(light: 0xEBF0F4, dark: 0x1B1D2C)
    /// Card fill and hairline.
    static let card = Color(light: 0xFFFFFF, lightAlpha: 0.62, dark: 0xFFFFFF, darkAlpha: 0.045)
    static let cardStrong = Color(light: 0xFFFFFF, lightAlpha: 0.85, dark: 0xFFFFFF, darkAlpha: 0.08)
    static let hairline = Color(light: 0x3C4A40, lightAlpha: 0.10, dark: 0xD8E4F0, darkAlpha: 0.10)
    static let shadow = Color(light: 0x3C4A40, lightAlpha: 0.08, dark: 0x000000, darkAlpha: 0.30)

    // MARK: Text

    static let ink = Color(light: 0x2F3A34, dark: 0xE4E8E6)
    static let inkSoft = Color(light: 0x5F6B64, dark: 0xA9B3B0)
    static let inkFaint = Color(light: 0x8E978F, dark: 0x76807F)

    // MARK: Accents

    static let sage = Color(light: 0x6E8B74, dark: 0x8FB3A0)
    static let moss = Color(light: 0x56735E, dark: 0x7FA493)
    static let mist = Color(light: 0x7A9BB0, dark: 0x7F9CC0)
    static let sand = Color(light: 0xC9A36B, dark: 0xCFAE7E)
    static let clay = Color(light: 0xB8694F, dark: 0xD48E76)
    static let dusk = Color(light: 0x8D84B0, dark: 0x9C93C4)

    // MARK: Gradients

    /// Background of the menu popover and the main window. Barely there.
    static let background = LinearGradient(colors: [washStart, paper, washEnd],
                                           startPoint: .top, endPoint: .bottom)
    /// Sage to mist (light) / muted teal to indigo (dark): the calm accent gradient.
    static let calm = LinearGradient(colors: [Color(light: 0x8FAE92, dark: 0x5E9A93), Color(light: 0x89A7BC, dark: 0x6670A8)],
                                     startPoint: .topLeading, endPoint: .bottomTrailing)
    /// A paler version of `calm` for large surfaces such as the selected tab.
    static let calmSoft = LinearGradient(colors: [sage.opacity(0.20), mist.opacity(0.20)],
                                         startPoint: .topLeading, endPoint: .bottomTrailing)

    /// Deeper version of `calm`, for white text on prominent buttons.
    static let calmDeep = LinearGradient(colors: [Color(light: 0x5F8068, dark: 0x4E8580), Color(light: 0x5E7F98, dark: 0x5A63A0)],
                                         startPoint: .topLeading, endPoint: .bottomTrailing)
    /// Behind the "What this means" advice.
    static let adviceWash = LinearGradient(colors: [sage.opacity(0.13), mist.opacity(0.09)],
                                           startPoint: .topLeading, endPoint: .bottomTrailing)

    static let cardRadius: CGFloat = 14
}

extension Severity {
    /// Gentle but distinguishable: stone, mist, sand, clay, plum.
    var color: Color {
        switch self {
        case .info: return Color(light: 0x9A958C, dark: 0x8E8C87)
        case .low: return Color(light: 0x7F9FB5, dark: 0x7E9DB4)
        case .medium: return Color(light: 0xD0A15E, dark: 0xC9A06A)
        case .high: return Color(light: 0xC77B5E, dark: 0xC98468)
        case .critical: return Color(light: 0xA35A7C, dark: 0xB97C9C)
        }
    }

    /// Text colour on a tint of `color`, with enough contrast to read.
    var ink: Color {
        switch self {
        case .info: return Color(light: 0x6B675F, dark: 0xC2BFB8)
        case .low: return Color(light: 0x44657C, dark: 0xAECADF)
        case .medium: return Color(light: 0x85602A, dark: 0xE6C99B)
        case .high: return Color(light: 0x9A4A30, dark: 0xEDB29A)
        case .critical: return Color(light: 0x7E3557, dark: 0xE8B4CD)
        }
    }

    var gradient: LinearGradient {
        LinearGradient(colors: [color.opacity(0.75), color], startPoint: .topLeading, endPoint: .bottomTrailing)
    }

    /// High and critical get a slightly stronger tint so they never blend in.
    var tintOpacity: Double { self >= .high ? 0.22 : 0.15 }
}

extension Color {
    /// A colour that follows the appearance of the view it is drawn in.
    init(light: UInt32, lightAlpha: CGFloat = 1, dark: UInt32, darkAlpha: CGFloat = 1) {
        self.init(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            return NSColor(hex: isDark ? dark : light, alpha: isDark ? darkAlpha : lightAlpha)
        })
    }
}

private extension NSColor {
    convenience init(hex: UInt32, alpha: CGFloat) {
        self.init(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                  blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
    }
}

// MARK: Building blocks

extension View {
    /// A soft rounded card: translucent fill, hairline border, faint shadow.
    func zenCard(padding: CGFloat = 14, radius: CGFloat = Theme.cardRadius) -> some View {
        let shape = RoundedRectangle(cornerRadius: radius, style: .continuous)
        return self
            .padding(padding)
            .background(Theme.card, in: shape)
            .overlay(shape.strokeBorder(Theme.hairline, lineWidth: 0.5))
            .shadow(color: Theme.shadow, radius: 8, y: 3)
    }

    /// The calm background wash behind a whole window or popover.
    func zenBackground() -> some View {
        background(Theme.background.ignoresSafeArea())
    }
}

/// A small rounded square with a soft tinted gradient and an SF Symbol inside.
struct Squircle: View {
    let symbol: String
    var tint: Color = Theme.sage
    var size: CGFloat = 26

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.32, style: .continuous)
        Image(systemName: symbol)
            .font(.system(size: size * 0.48, weight: .medium))
            .foregroundStyle(tint)
            .frame(width: size, height: size)
            .background(LinearGradient(colors: [tint.opacity(0.14), tint.opacity(0.26)],
                                       startPoint: .topLeading, endPoint: .bottomTrailing), in: shape)
            .overlay(shape.strokeBorder(tint.opacity(0.18), lineWidth: 0.5))
    }
}

/// Paths and commands: small monospaced text in a softly tinted box.
struct MonoBox: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 11, design: .monospaced))
            .fontDesign(.monospaced)
            .foregroundStyle(Theme.inkSoft)
            .textSelection(.enabled)
            .lineSpacing(2)
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.mist.opacity(0.10), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous).strokeBorder(Theme.mist.opacity(0.16), lineWidth: 0.5))
    }
}

/// Rounded capsule buttons; `prominent` uses the calm gradient.
struct SoftButtonStyle: ButtonStyle {
    var prominent = false
    var destructive = false
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12.5, weight: .medium, design: .rounded))
            .foregroundStyle(prominent ? Color.white : (destructive ? Severity.high.ink : Theme.ink))
            .padding(.horizontal, 13)
            .padding(.vertical, 6)
            .background {
                Capsule(style: .continuous).fill(prominent ? AnyShapeStyle(Theme.calmDeep) : AnyShapeStyle(Theme.cardStrong))
            }
            .overlay(Capsule(style: .continuous).strokeBorder(prominent ? Color.white.opacity(0.15) : Theme.hairline, lineWidth: 0.5))
            .shadow(color: Theme.shadow, radius: prominent ? 4 : 2, y: 1)
            .opacity(isEnabled ? (configuration.isPressed ? 0.75 : 1) : 0.45)
            .contentShape(Capsule())
    }
}

/// A small heading over a group of content.
struct SectionLabel: View {
    let title: String
    init(_ title: String) { self.title = title }

    var body: some View {
        Text(title)
            .font(.system(size: 11.5, weight: .semibold, design: .rounded))
            .foregroundStyle(Theme.inkFaint)
    }
}
