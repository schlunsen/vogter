import SwiftUI

struct MainWindow: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        MainWindowContent(selection: $model.selectedTab)
            .onAppear { model.refresh() }
    }
}

/// The tab strip and the selected tab, on the calm background. Shared with the
/// screenshot renderer, so the README shows exactly this.
struct MainWindowContent: View {
    @Binding var selection: String

    static let tabs: [(id: String, title: String, symbol: String)] = [
        ("findings", "Findings", "shield"),
        ("activity", "Activity", "list.bullet"),
        ("trusted", "Trusted", "hand.thumbsup"),
        ("status", "Status", "gauge"),
    ]

    var body: some View {
        VStack(spacing: 16) {
            ZenTabBar(selection: $selection)
            Group {
                switch selection {
                case "activity": ActivityTab()
                case "trusted": TrustedTab()
                case "status": StatusTab()
                default: FindingsTab()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(.horizontal, 20)
        .padding(.top, 14)
        .padding(.bottom, 20)
        .fontDesign(.rounded)
        .tint(Theme.sage)
        .zenBackground()
    }
}

/// A soft segmented control: a translucent capsule with the selected tab raised.
struct ZenTabBar: View {
    @Binding var selection: String

    var body: some View {
        HStack(spacing: 2) {
            ForEach(MainWindowContent.tabs, id: \.id) { tab in
                let selected = tab.id == selection
                Button { selection = tab.id } label: {
                    HStack(spacing: 6) {
                        Image(systemName: tab.symbol).font(.system(size: 11, weight: .medium))
                        Text(tab.title).font(.system(size: 12.5, weight: selected ? .semibold : .regular, design: .rounded))
                    }
                    .foregroundStyle(selected ? Theme.ink : Theme.inkSoft)
                    .padding(.horizontal, 14)
                    .frame(height: 26)
                    .background {
                        if selected {
                            Capsule(style: .continuous)
                                .fill(Theme.cardStrong)
                                .overlay(Capsule(style: .continuous).fill(Theme.calmSoft))
                                .overlay(Capsule(style: .continuous).strokeBorder(Theme.hairline, lineWidth: 0.5))
                                .shadow(color: Theme.shadow, radius: 3, y: 1)
                        }
                    }
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(3)
        .background(Theme.card, in: Capsule(style: .continuous))
        .overlay(Capsule(style: .continuous).strokeBorder(Theme.hairline, lineWidth: 0.5))
    }
}

struct FindingsTab: View {
    @Environment(AppModel.self) private var model
    @State private var minimum: Severity = .low

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Picker("Show", selection: $minimum) {
                    ForEach(Severity.allCases, id: \.self) { Text("\($0.label) and up").tag($0) }
                }
                .frame(width: 220)
                Spacer()
                Button("Scan now") { model.scanNow() }
                    .buttonStyle(SoftButtonStyle(prominent: true))
                    .disabled(!model.connected)
            }
            if !model.connected {
                NotRunningView().zenCard(padding: 18).frame(maxWidth: 420, alignment: .leading)
                Spacer()
            } else {
                let items = model.findings.filter { $0.severity >= minimum }
                if items.isEmpty {
                    CalmEmptyState(symbol: "leaf", title: "Nothing needs your attention",
                                   message: "Breathe easy — Vogter keeps watching quietly.")
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 10) {
                            ForEach(items) { f in
                                FindingRow(finding: f).zenCard(padding: 14)
                            }
                        }
                        .padding(8)
                    }
                    .padding(-8)
                }
            }
        }
    }
}

struct ActivityTab: View {
    @Environment(AppModel.self) private var model
    @State private var alertsOnly = false

    var body: some View {
        @Bindable var model = model
        let items = model.events.filter { !alertsOnly || ($0.severity ?? .info) >= .low }
        HSplitView {
            VStack(alignment: .leading, spacing: 8) {
                Toggle("Alerts only", isOn: $alertsOnly)
                    .toggleStyle(.checkbox)
                    .font(.system(size: 11.5, design: .rounded))
                    .foregroundStyle(Theme.inkSoft)
                    .padding(.leading, 4)
                List(items, selection: $model.selectedEventID) { e in
                    HStack(alignment: .top, spacing: 10) {
                        Squircle(symbol: e.symbol, tint: e.severity.map(\.color) ?? Theme.inkFaint, size: 22)
                        Text(e.text)
                            .font(.system(size: 12.5, design: .rounded))
                            .foregroundStyle(Theme.ink)
                            .lineLimit(2)
                            .padding(.top, 2)
                        Spacer()
                        if let sev = e.severity, sev > .info { SeverityBadge(severity: sev).padding(.top, 1) }
                        Text(Date(timeIntervalSince1970: TimeInterval(e.at)), style: .time)
                            .foregroundStyle(Theme.inkFaint)
                            .font(.system(size: 11, design: .rounded))
                            .monospacedDigit()
                            .padding(.top, 3)
                    }
                    .padding(.vertical, 3)
                    .tag(e.id)
                }
                .scrollContentBackground(.hidden)
                .background(Theme.card, in: RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 0.5))
            }
            .padding(.trailing, 10)
            .frame(minWidth: 320, idealWidth: 380)

            Group {
                if let e = model.selectedEvent {
                    EventDetail(event: e).id(e.id)
                } else {
                    CalmEmptyState(symbol: "hand.point.left", title: "Choose an event",
                                   message: "Its details and what you can do about it appear here.")
                }
            }
            .padding(.leading, 10)
            .frame(minWidth: 360, maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

/// A quiet, centred message for empty places.
struct CalmEmptyState: View {
    let symbol: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 10) {
            Squircle(symbol: symbol, tint: Theme.sage, size: 48)
            Text(title).font(.system(size: 15, weight: .semibold, design: .rounded)).foregroundStyle(Theme.ink)
            Text(message)
                .font(.system(size: 12, design: .rounded))
                .foregroundStyle(Theme.inkSoft)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 300)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct TrustedTab: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if model.trustRules.isEmpty {
            CalmEmptyState(symbol: "hand.thumbsup", title: "Nothing trusted yet",
                           message: "Use the thumbs-up on a finding or activity to stop alerts about an app you know.")
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    ForEach(model.trustRules) { r in
                        HStack(spacing: 12) {
                            Squircle(symbol: r.symbol, tint: Theme.sage, size: 30)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(r.label)
                                    .font(.system(size: 13, weight: .medium, design: .rounded))
                                    .foregroundStyle(Theme.ink)
                                    .textSelection(.enabled)
                                Text("\(r.subject.kindLabel) · \(r.check == "*" ? "all alerts" : r.check) · added \(relativeTime(r.createdAt))")
                                    .font(.system(size: 11.5, design: .rounded)).foregroundStyle(Theme.inkSoft)
                            }
                            Spacer()
                            Button("Remove") { model.untrust(r) }.buttonStyle(SoftButtonStyle())
                        }
                        .zenCard(padding: 14)
                    }
                }
                .padding(8)
            }
            .padding(-8)
        }
    }
}

private extension TrustRule {
    var symbol: String {
        switch subject {
        case .developer: return "checkmark.seal"
        case .file: return "doc"
        case .exact: return "bell.slash"
        case .unknown: return "hand.thumbsup"
        }
    }
}

struct StatusTab: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if let s = model.status {
                    group("Service", symbol: "server.rack") {
                        row("Service", "vogterd \(s.version)\(s.asRoot ? " (root)" : " (user mode)")")
                        row("Socket", model.socketPath ?? "-")
                        row("Scan interval", "\(s.scanIntervalSecs) s")
                        if let last = s.lastScan { row("Last scan", relativeTime(last)) }
                        if let until = s.learningUntil, until > UInt64(Date().timeIntervalSince1970) {
                            row("Learning", "until \(Date(timeIntervalSince1970: TimeInterval(until)).formatted(date: .abbreviated, time: .omitted))")
                        }
                        row("Trust rules", "\(s.trustRules ?? 0)", last: true)
                    }
                    group("Watching", symbol: "eye") {
                        if let rt = s.realtime {
                            row("Realtime", rt.sources.joined(separator: ", "))
                            row("Endpoint Security", rt.endpointSecurity ? "active" : "off", last: rt.endpointSecurityError == nil)
                            if let err = rt.endpointSecurityError {
                                note(err).padding(.top, 6)
                                Divider().overlay(Theme.hairline).padding(.vertical, 6)
                            }
                        }
                        row("Microphone", s.av.microphoneInUse ? "in use" : "off")
                        row("Camera", s.av.cameraInUse ? "in use" : "off", last: true)
                    }
                    group("Limited visibility", symbol: "eye.slash") {
                        if s.sensorErrors.isEmpty {
                            Text("None — Vogter can see everything it looks for")
                                .font(.system(size: 12.5, design: .rounded)).foregroundStyle(Theme.inkSoft)
                        }
                        ForEach(s.sensorErrors, id: \.self) { note($0) }
                        if !s.asRoot {
                            note("Running as your user. Install the service as root to see all processes.")
                        }
                    }
                } else {
                    NotRunningView().zenCard(padding: 18)
                }
                if let err = model.lastError {
                    group("Last error", symbol: "exclamationmark.bubble") {
                        Text(err).font(.system(size: 12.5, design: .rounded)).foregroundStyle(Severity.high.ink).textSelection(.enabled)
                    }
                }
            }
            .frame(maxWidth: 640)
            .padding(8)
            .frame(maxWidth: .infinity)
        }
        .padding(-8)
    }

    private func group<Content: View>(_ title: String, symbol: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: symbol)
                .font(.system(size: 11.5, weight: .semibold, design: .rounded))
                .foregroundStyle(Theme.inkFaint)
                .padding(.leading, 4)
            VStack(alignment: .leading, spacing: 0) { content() }
                .frame(maxWidth: .infinity, alignment: .leading)
                .zenCard(padding: 14)
        }
    }

    private func row(_ label: String, _ value: String, last: Bool = false) -> some View {
        VStack(spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text(label).foregroundStyle(Theme.ink)
                Spacer(minLength: 16)
                Text(value).foregroundStyle(Theme.inkSoft).multilineTextAlignment(.trailing)
            }
            .font(.system(size: 12.5, design: .rounded))
            .padding(.vertical, 6)
            if !last { Divider().overlay(Theme.hairline) }
        }
    }

    private func note(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 11.5, design: .rounded))
            .foregroundStyle(Theme.inkSoft)
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
    }
}
