import SwiftUI

extension Severity {
    var color: Color {
        switch self {
        case .info: return .secondary
        case .low: return .blue
        case .medium: return .orange
        case .high: return .red
        case .critical: return .purple
        }
    }
}

struct SeverityBadge: View {
    let severity: Severity

    var body: some View {
        Text(severity.label.uppercased())
            .font(.system(size: 9, weight: .bold))
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .foregroundStyle(severity == .info ? Color.primary : Color.white)
            .background(severity.color.opacity(severity == .info ? 0.2 : 1), in: RoundedRectangle(cornerRadius: 3))
    }
}

struct FindingRow: View {
    @Environment(AppModel.self) private var model
    let finding: StoredFinding
    var compact = false

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            SeverityBadge(severity: finding.severity)
                .frame(width: 62, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text(finding.title).font(.callout.weight(.medium))
                Text(finding.detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(compact ? 2 : nil)
                    .textSelection(.enabled)
                if !compact, let path = finding.path {
                    Text(path).font(.caption.monospaced()).foregroundStyle(.tertiary).textSelection(.enabled)
                }
                Text("First seen \(relativeTime(finding.firstSeen))")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            Spacer(minLength: 4)
            if finding.path != nil {
                Button { model.reveal(finding) } label: { Image(systemName: "folder") }
                    .buttonStyle(.borderless)
                    .help("Show in Finder")
            }
            Button { model.acknowledge(finding) } label: { Image(systemName: "checkmark.circle") }
                .buttonStyle(.borderless)
                .help("I know about this — hide it until it goes away and comes back")
            Menu {
                Button("Trust for this kind of alert") { model.trust(finding) }
                Button("Trust for all alerts") { model.trust(finding, allChecks: true) }
            } label: { Image(systemName: "hand.thumbsup") }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("Trust this app or file permanently")
        }
        .padding(.vertical, 3)
    }
}

struct LiveIndicators: View {
    let av: AvState

    var body: some View {
        if av.microphoneInUse {
            let who = av.microphoneClients.map(\.name).joined(separator: ", ")
            Label(who.isEmpty ? "Microphone in use" : "Microphone in use by \(who)", systemImage: "mic.fill")
                .foregroundStyle(.red)
        }
        if av.cameraInUse {
            Label("Camera in use", systemImage: "video.fill").foregroundStyle(.red)
        }
    }
}

struct NotRunningView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Vogter service is not running", systemImage: "bolt.horizontal.circle")
                .font(.headline)
            Text("Start it from the project folder:")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("cargo run --release -p vogterd")
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .padding(6)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 4))
            Text("Reconnecting automatically…").font(.caption2).foregroundStyle(.tertiary)
        }
    }
}
