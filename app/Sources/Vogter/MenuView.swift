import SwiftUI

struct MenuView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: 14) {
            header
            if !model.connected {
                NotRunningView().zenCard()
            } else {
                if let av = model.status?.av, av.microphoneInUse || av.cameraInUse {
                    VStack(alignment: .leading, spacing: 6) { LiveIndicators(av: av) }
                }
                if !model.recentAlerts.isEmpty {
                    recentAlerts
                }
                findingsList
            }
            HStack(spacing: 8) {
                Button("Scan now") { model.scanNow() }
                    .buttonStyle(SoftButtonStyle(prominent: true))
                    .disabled(!model.connected || model.status?.scanning == true)
                Button("Open Vogter") {
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                }
                .buttonStyle(SoftButtonStyle())
                Spacer()
                Toggle("Info", isOn: $model.showInfo)
                    .toggleStyle(.checkbox)
                    .font(.system(size: 11.5, design: .rounded))
                    .foregroundStyle(Theme.inkSoft)
                Button { NSApp.terminate(nil) } label: {
                    Image(systemName: "power").font(.system(size: 12)).foregroundStyle(Theme.inkSoft)
                }
                .buttonStyle(.borderless)
                .help("Quit Vogter")
            }
        }
        .padding(16)
        .frame(width: 400)
        .fontDesign(.rounded)
        .tint(Theme.sage)
        .zenBackground()
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: model.menuBarSymbol)
                .font(.system(size: 17, weight: .medium))
                .foregroundStyle(.white)
                .frame(width: 38, height: 38)
                .background(moodGradient, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .shadow(color: Theme.shadow, radius: 4, y: 2)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text("Vogter").font(.system(size: 15, weight: .semibold, design: .rounded)).foregroundStyle(Theme.ink)
                    Text("·").foregroundStyle(Theme.inkFaint)
                    Text(mood).font(.system(size: 13.5, weight: .medium, design: .rounded)).foregroundStyle(moodInk)
                }
                Text(subtitle).font(.system(size: 11.5, design: .rounded)).foregroundStyle(Theme.inkSoft)
            }
            Spacer()
        }
    }

    /// Honest but gentle: medium asks for a look, high and critical ask clearly.
    private var mood: String {
        guard model.connected else { return "Resting" }
        switch model.worst {
        case .critical?, .high?: return "Please take a look"
        case .medium?: return "Something needs a look"
        default: return "All calm"
        }
    }

    private var moodInk: Color {
        guard model.connected else { return Theme.inkSoft }
        if let w = model.worst, w >= .medium { return w.ink }
        return Theme.moss
    }

    private var moodGradient: LinearGradient {
        guard model.connected else {
            return LinearGradient(colors: [Theme.dusk.opacity(0.7), Theme.mist.opacity(0.8)], startPoint: .topLeading, endPoint: .bottomTrailing)
        }
        if let w = model.worst, w >= .medium { return w.gradient }
        return Theme.calm
    }

    private var subtitle: String {
        guard model.connected, let s = model.status else { return "The Vogter service isn't running" }
        if s.scanning { return "Looking around…" }
        guard let last = s.lastScan else { return "Waiting for the first scan" }
        return "Last scan \(relativeTime(last)) · every \(s.scanIntervalSecs / 60) min"
    }

    private var recentAlerts: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionLabel("Recent alerts")
            VStack(alignment: .leading, spacing: 10) {
                ForEach(model.recentAlerts.prefix(4)) { e in
                    Button {
                        model.select(eventID: e.id)
                        openWindow(id: "main")
                        NSApp.activate(ignoringOtherApps: true)
                    } label: {
                        HStack(alignment: .top, spacing: 10) {
                            Squircle(symbol: e.symbol, tint: e.severity?.color ?? Theme.inkFaint, size: 22)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(e.text)
                                    .font(.system(size: 12.5, design: .rounded))
                                    .foregroundStyle(Theme.ink)
                                    .lineLimit(2)
                                    .multilineTextAlignment(.leading)
                                    .fixedSize(horizontal: false, vertical: true)
                                Text(relativeTime(e.at)).font(.system(size: 10.5, design: .rounded)).foregroundStyle(Theme.inkFaint)
                            }
                            Spacer(minLength: 4)
                            Image(systemName: "chevron.right").font(.system(size: 10, weight: .medium)).foregroundStyle(Theme.inkFaint)
                                .padding(.top, 4)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help("Show details and actions")
                }
            }
            .zenCard(padding: 12)
        }
    }

    @ViewBuilder private var findingsList: some View {
        let items = model.visibleFindings
        if items.isEmpty {
            HStack(spacing: 10) {
                Squircle(symbol: "leaf", tint: Theme.sage, size: 28)
                Text("Nothing needs your attention — breathe easy")
                    .font(.system(size: 12.5, design: .rounded))
                    .foregroundStyle(Theme.inkSoft)
                Spacer(minLength: 0)
            }
            .zenCard(padding: 12)
        } else {
            VStack(alignment: .leading, spacing: 8) {
                SectionLabel("Worth a look")
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 6) {
                        ForEach(Array(items.enumerated()), id: \.element.id) { i, f in
                            if i > 0 { Divider().overlay(Theme.hairline).padding(.leading, 36) }
                            FindingRow(finding: f, compact: true)
                        }
                    }
                }
                .frame(maxHeight: 420)
                .fixedSize(horizontal: false, vertical: true)
                .zenCard(padding: 12)
            }
        }
    }
}
