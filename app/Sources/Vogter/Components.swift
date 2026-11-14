import SwiftUI

/// A soft pill: a gradient dot and the severity in sentence case ("High").
struct SeverityBadge: View {
    let severity: Severity

    var body: some View {
        HStack(spacing: 4) {
            Circle().fill(severity.gradient).frame(width: 6, height: 6)
            Text(severity.label)
                .font(.system(size: 10.5, weight: severity >= .high ? .semibold : .medium, design: .rounded))
                .foregroundStyle(severity.ink)
        }
        .padding(.leading, 6)
        .padding(.trailing, 8)
        .padding(.vertical, 2.5)
        .background(severity.color.opacity(severity.tintOpacity), in: Capsule(style: .continuous))
        .overlay(Capsule(style: .continuous).strokeBorder(severity.color.opacity(0.25), lineWidth: 0.5))
        .fixedSize()
        .accessibilityLabel("Severity: \(severity.label)")
    }
}

extension StoredFinding {
    var symbol: String {
        switch category {
        case "keylogger": return "keyboard"
        case "privacy": return "hand.raised"
        case "process": return "terminal"
        case "persistence": return "arrow.clockwise"
        case "network": return "network"
        case "system_health": return "heart"
        case "browser": return "puzzlepiece.extension"
        default: return "sparkle"
        }
    }
}

struct FindingRow: View {
    @Environment(AppModel.self) private var model
    let finding: StoredFinding
    var compact = false

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Squircle(symbol: finding.symbol, tint: finding.severity.color, size: compact ? 26 : 30)
            VStack(alignment: .leading, spacing: 3) {
                Text(finding.title)
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundStyle(Theme.ink)
                Text(finding.detail)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.inkSoft)
                    .lineLimit(compact ? 2 : nil)
                    .textSelection(.enabled)
                if !compact, let path = finding.path {
                    MonoBox(text: path).padding(.top, 2)
                }
                HStack(spacing: 6) {
                    SeverityBadge(severity: finding.severity)
                    Text("First seen \(relativeTime(finding.firstSeen))")
                        .font(.system(size: 10.5, design: .rounded))
                        .foregroundStyle(Theme.inkFaint)
                }
                .padding(.top, 2)
            }
            Spacer(minLength: 4)
            HStack(spacing: 2) {
                if finding.path != nil {
                    Button { model.reveal(finding) } label: { RowIcon(symbol: "folder") }
                        .buttonStyle(.plain)
                        .help("Show in Finder")
                }
                Button { model.acknowledge(finding) } label: { RowIcon(symbol: "checkmark.circle") }
                    .buttonStyle(.plain)
                    .help("I know about this — hide it until it goes away and comes back")
                Menu {
                    Button("Trust for this kind of alert") { model.trust(finding) }
                    Button("Trust for all alerts") { model.trust(finding, allChecks: true) }
                } label: { RowIcon(symbol: "hand.thumbsup") }
                    .menuStyle(.borderlessButton)
                    .menuIndicator(.hidden)
                    .fixedSize()
                    .help("Trust this app or file permanently")
            }
        }
        .padding(.vertical, 4)
    }
}

/// A quiet icon for row actions.
private struct RowIcon: View {
    let symbol: String

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 12.5))
            .foregroundStyle(Theme.inkSoft)
            .frame(width: 24, height: 24)
            .contentShape(Rectangle())
    }
}

struct LiveIndicators: View {
    let av: AvState

    var body: some View {
        if av.microphoneInUse {
            let who = av.microphoneClients.map(\.name).joined(separator: ", ")
            indicator(who.isEmpty ? "Microphone in use" : "Microphone in use by \(who)", symbol: "mic.fill")
        }
        if av.cameraInUse {
            indicator("Camera in use", symbol: "video.fill")
        }
    }

    private func indicator(_ text: String, symbol: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: symbol)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 22, height: 22)
                .background(Severity.high.gradient, in: Circle())
            Text(text)
                .font(.system(size: 12.5, weight: .medium, design: .rounded))
                .foregroundStyle(Severity.high.ink)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(Severity.high.color.opacity(0.13), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

struct NotRunningView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Squircle(symbol: "moon.zzz", tint: Theme.dusk, size: 30)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Resting")
                        .font(.system(size: 14, weight: .semibold, design: .rounded))
                        .foregroundStyle(Theme.ink)
                    Text("The Vogter service isn't running")
                        .font(.system(size: 12, design: .rounded))
                        .foregroundStyle(Theme.inkSoft)
                }
            }
            Text("Start it from the project folder:")
                .font(.system(size: 11.5, design: .rounded))
                .foregroundStyle(Theme.inkSoft)
            MonoBox(text: "cargo run --release -p vogterd")
            Text("Vogter will reconnect on its own…")
                .font(.system(size: 10.5, design: .rounded))
                .foregroundStyle(Theme.inkFaint)
        }
    }
}
