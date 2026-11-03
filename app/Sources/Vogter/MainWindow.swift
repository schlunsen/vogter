import SwiftUI

struct MainWindow: View {
    @Environment(AppModel.self) private var model
    @State private var tab = "findings"

    var body: some View {
        TabView(selection: $tab) {
            FindingsTab().tabItem { Label("Findings", systemImage: "exclamationmark.shield") }.tag("findings")
            ActivityTab().tabItem { Label("Activity", systemImage: "list.bullet.rectangle") }.tag("activity")
            StatusTab().tabItem { Label("Status", systemImage: "gauge") }.tag("status")
        }
        .padding()
        .onAppear { model.refresh() }
    }
}

private struct FindingsTab: View {
    @Environment(AppModel.self) private var model
    @State private var minimum: Severity = .low

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Picker("Show", selection: $minimum) {
                    ForEach(Severity.allCases, id: \.self) { Text("\($0.label) and up").tag($0) }
                }
                .frame(width: 220)
                Spacer()
                Button("Scan now") { model.scanNow() }.disabled(!model.connected)
            }
            if !model.connected {
                NotRunningView().padding()
                Spacer()
            } else {
                List(model.findings.filter { $0.severity >= minimum }) { f in
                    FindingRow(finding: f)
                }
            }
        }
    }
}

private struct ActivityTab: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        List(model.events) { e in
            HStack(alignment: .top) {
                Image(systemName: e.symbol)
                    .frame(width: 20)
                    .foregroundStyle(e.severity.map(\.color) ?? .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(e.text)
                    if let d = e.detail {
                        Text(d).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
                Spacer()
                if let sev = e.severity, sev > .info { SeverityBadge(severity: sev) }
                Text(Date(timeIntervalSince1970: TimeInterval(e.at)), style: .time)
                    .foregroundStyle(.secondary)
                    .font(.caption)
            }
        }
    }
}

private struct StatusTab: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Form {
            if let s = model.status {
                LabeledContent("Service", value: "vogterd \(s.version)\(s.asRoot ? " (root)" : " (user mode)")")
                LabeledContent("Socket", value: model.socketPath ?? "-")
                LabeledContent("Scan interval", value: "\(s.scanIntervalSecs) s")
                if let last = s.lastScan { LabeledContent("Last scan", value: relativeTime(last)) }
                if let rt = s.realtime {
                    LabeledContent("Realtime", value: rt.sources.joined(separator: ", "))
                    LabeledContent("Endpoint Security", value: rt.endpointSecurity ? "active" : "off")
                    if let err = rt.endpointSecurityError {
                        Text(err).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                }
                LabeledContent("Microphone", value: s.av.microphoneInUse ? "in use" : "off")
                LabeledContent("Camera", value: s.av.cameraInUse ? "in use" : "off")
                Section("Limited visibility") {
                    if s.sensorErrors.isEmpty {
                        Text("None").foregroundStyle(.secondary)
                    }
                    ForEach(s.sensorErrors, id: \.self) { Text($0).font(.caption).textSelection(.enabled) }
                    if !s.asRoot {
                        Text("Running as your user. Install the service as root to see all processes.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } else {
                NotRunningView()
            }
            if let err = model.lastError {
                Section("Last error") { Text(err).foregroundStyle(.red) }
            }
        }
        .formStyle(.grouped)
    }
}
