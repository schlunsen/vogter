import SwiftUI

struct MainWindow: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        TabView(selection: $model.selectedTab) {
            FindingsTab().tabItem { Label("Findings", systemImage: "exclamationmark.shield") }.tag("findings")
            ActivityTab().tabItem { Label("Activity", systemImage: "list.bullet.rectangle") }.tag("activity")
            TrustedTab().tabItem { Label("Trusted", systemImage: "hand.thumbsup") }.tag("trusted")
            StatusTab().tabItem { Label("Status", systemImage: "gauge") }.tag("status")
        }
        .padding()
        .onAppear { model.refresh() }
    }
}

struct FindingsTab: View {
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

struct ActivityTab: View {
    @Environment(AppModel.self) private var model
    @State private var alertsOnly = false

    var body: some View {
        @Bindable var model = model
        let items = model.events.filter { !alertsOnly || ($0.severity ?? .info) >= .low }
        HSplitView {
            VStack(alignment: .leading, spacing: 6) {
                Toggle("Alerts only", isOn: $alertsOnly).toggleStyle(.checkbox).font(.caption)
                List(items, selection: $model.selectedEventID) { e in
                    HStack(alignment: .top) {
                        Image(systemName: e.symbol)
                            .frame(width: 20)
                            .foregroundStyle(e.severity.map(\.color) ?? .secondary)
                        Text(e.text).lineLimit(2)
                        Spacer()
                        if let sev = e.severity, sev > .info { SeverityBadge(severity: sev) }
                        Text(Date(timeIntervalSince1970: TimeInterval(e.at)), style: .time)
                            .foregroundStyle(.secondary)
                            .font(.caption)
                    }
                    .tag(e.id)
                }
            }
            .frame(minWidth: 320, idealWidth: 380)

            Group {
                if let e = model.selectedEvent {
                    EventDetail(event: e).id(e.id)
                } else {
                    VStack(spacing: 8) {
                        Image(systemName: "hand.point.left").font(.largeTitle).foregroundStyle(.secondary)
                        Text("Select an event to see details and actions").foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .frame(minWidth: 360, maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

/// Everything known about one event, and what you can do about it.
private struct EventDetail: View {
    @Environment(AppModel.self) private var model
    let event: LoggedEvent
    @State private var confirmQuit = false
    @State private var trusted = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline) {
                    if let sev = event.severity { SeverityBadge(severity: sev) }
                    Text(event.text).font(.title3.weight(.semibold)).textSelection(.enabled)
                }
                Text(Date(timeIntervalSince1970: TimeInterval(event.at)).formatted(date: .abbreviated, time: .standard))
                    .font(.caption).foregroundStyle(.secondary)

                if case let .activity(a) = event.kind {
                    activityBody(a)
                } else if case let .newFinding(f) = event.kind {
                    section("Details") { Text(f.detail).textSelection(.enabled) }
                    if let p = f.path { section("Location") { mono(p) } }
                    Text("Act on it from the Findings tab.").font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("No further details for this event.").foregroundStyle(.secondary)
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private func activityBody(_ a: Activity) -> some View {
        if let advice = a.advice {
            section("What this means") {
                Text(advice).textSelection(.enabled)
            }
        }
        section("Program") {
            VStack(alignment: .leading, spacing: 4) {
                if let p = a.process {
                    LabeledContent("Name", value: p)
                }
                if let pid = a.pid {
                    let running = model.isRunning(pid: pid, path: a.path)
                    LabeledContent("Process", value: "pid \(pid) · \(running ? "still running" : "no longer running")")
                }
                if let s = a.signing {
                    LabeledContent("Signature", value: s.summary + (s.identifier.map { " · \($0)" } ?? ""))
                }
                if let p = a.path { LabeledContent("Location") { mono(p) } }
            }
        }
        if let d = a.detail {
            section("Command and origin") { mono(d) }
        }

        HStack {
            Menu("Trust…") {
                Button("Trust for this kind of alert") { model.trust(event); trusted = true }
                Button("Trust for all alerts") { model.trust(event, allChecks: true); trusted = true }
            }
            .fixedSize()
            .help("Stop alerts about this program. Signed apps are trusted by developer; unsigned files by their exact contents.")
            .disabled(trusted)
            if let p = a.path {
                Button("Show in Finder") { model.reveal(path: p) }
            }
            Button("Copy details") { model.copyDetails(event) }
            if let pid = a.pid, model.isRunning(pid: pid, path: a.path) {
                Button("Quit program…", role: .destructive) { confirmQuit = true }
                    .confirmationDialog("Quit \(a.process ?? "this program")?", isPresented: $confirmQuit) {
                        Button("Quit", role: .destructive) { model.terminate(pid: pid) }
                    } message: {
                        Text("Vogter asks it to quit (like Activity Monitor). Unsaved work in it may be lost.")
                    }
            }
        }
        if trusted {
            Label("Trusted. Future alerts about this program are hidden — manage in the Trusted tab.", systemImage: "checkmark.circle")
                .font(.caption).foregroundStyle(.green)
        }
    }

    private func section<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            content()
        }
    }

    private func mono(_ s: String) -> some View {
        Text(s)
            .font(.system(.caption, design: .monospaced))
            .textSelection(.enabled)
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 4))
    }
}

struct TrustedTab: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if model.trustRules.isEmpty {
            VStack(spacing: 8) {
                Image(systemName: "hand.thumbsup").font(.largeTitle).foregroundStyle(.secondary)
                Text("Nothing trusted yet").font(.headline)
                Text("Use the thumbs-up on a finding or activity to stop alerts about an app you know.")
                    .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            List(model.trustRules) { r in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(r.label).textSelection(.enabled)
                        Text("\(r.subject.kindLabel) · \(r.check == "*" ? "all alerts" : r.check) · added \(relativeTime(r.createdAt))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Remove") { model.untrust(r) }
                }
            }
        }
    }
}

struct StatusTab: View {
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
                if let until = s.learningUntil, until > UInt64(Date().timeIntervalSince1970) {
                    LabeledContent("Learning", value: "until \(Date(timeIntervalSince1970: TimeInterval(until)).formatted(date: .abbreviated, time: .omitted))")
                }
                LabeledContent("Trust rules", value: "\(s.trustRules ?? 0)")
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
