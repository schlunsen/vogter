import SwiftUI

struct MenuView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: 10) {
            header
            Divider()
            if !model.connected {
                NotRunningView()
            } else {
                if let av = model.status?.av, av.microphoneInUse || av.cameraInUse {
                    VStack(alignment: .leading, spacing: 4) { LiveIndicators(av: av) }
                    Divider()
                }
                if !model.recentAlerts.isEmpty {
                    recentAlerts
                    Divider()
                }
                findingsList
            }
            Divider()
            HStack {
                Button("Scan now") { model.scanNow() }
                    .disabled(!model.connected || model.status?.scanning == true)
                Button("Open Vogter") {
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                }
                Spacer()
                Toggle("Info", isOn: $model.showInfo).toggleStyle(.checkbox).font(.caption)
                Button { NSApp.terminate(nil) } label: { Image(systemName: "power") }
                    .buttonStyle(.borderless)
                    .help("Quit Vogter")
            }
        }
        .padding(12)
        .frame(width: 400)
    }

    private var header: some View {
        HStack {
            Image(systemName: model.menuBarSymbol)
                .font(.title2)
                .foregroundStyle(model.worst?.color ?? .green)
            VStack(alignment: .leading) {
                Text("Vogter").font(.headline)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    private var subtitle: String {
        guard model.connected, let s = model.status else { return "Not connected" }
        if s.scanning { return "Scanning…" }
        guard let last = s.lastScan else { return "Waiting for first scan" }
        return "Last scan \(relativeTime(last)) · every \(s.scanIntervalSecs / 60) min"
    }

    private var recentAlerts: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Recent alerts").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            ForEach(model.recentAlerts.prefix(4)) { e in
                Button {
                    model.select(eventID: e.id)
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                } label: {
                    HStack(alignment: .top, spacing: 6) {
                        Image(systemName: e.symbol).foregroundStyle(e.severity?.color ?? .secondary).frame(width: 16)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(e.text).font(.callout).lineLimit(2).multilineTextAlignment(.leading)
                            Text(relativeTime(e.at)).font(.caption2).foregroundStyle(.tertiary)
                        }
                        Spacer(minLength: 4)
                        Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help("Show details and actions")
            }
        }
    }

    @ViewBuilder private var findingsList: some View {
        let items = model.visibleFindings
        if items.isEmpty {
            Label("Nothing needs your attention", systemImage: "checkmark.seal")
                .foregroundStyle(.secondary)
                .padding(.vertical, 8)
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    ForEach(items) { f in
                        FindingRow(finding: f, compact: true)
                        Divider()
                    }
                }
            }
            .frame(maxHeight: 420)
        }
    }
}
