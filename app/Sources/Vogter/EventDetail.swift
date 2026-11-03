import SwiftUI

/// Everything known about one event, and what you can do about it.
struct EventDetail: View {
    @Environment(AppModel.self) private var model
    let event: LoggedEvent
    @State private var confirmQuit = false
    @State private var trusted = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        if let sev = event.severity { SeverityBadge(severity: sev) }
                        Text(Date(timeIntervalSince1970: TimeInterval(event.at)).formatted(date: .abbreviated, time: .standard))
                            .font(.system(size: 11.5, design: .rounded)).foregroundStyle(Theme.inkFaint)
                    }
                    Text(event.text)
                        .font(.system(size: 17, weight: .semibold, design: .rounded))
                        .foregroundStyle(Theme.ink)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }

                if case let .activity(a) = event.kind {
                    activityBody(a)
                } else if case let .newFinding(f) = event.kind {
                    section("Details") { Text(f.detail).foregroundStyle(Theme.ink).textSelection(.enabled) }
                    if let p = f.path { section("Location") { MonoBox(text: p) } }
                    Text("Act on it from the Findings tab.").font(.caption).foregroundStyle(Theme.inkSoft)
                } else {
                    Text("No further details for this event.").foregroundStyle(Theme.inkSoft)
                }

                // Activities show these on their Program card.
                if case .activity = event.kind {} else if let path = event.programPath { programLinks(path) }
                noteCard
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 4)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .onAppear { draft = event.note ?? "" }
    }

    @State private var draft = ""

    /// "Who is this?" and "Show everything from this program".
    private func programLinks(_ path: String) -> some View {
        HStack(spacing: 16) {
            QuietLink(title: "Who is this?", symbol: "person.text.rectangle") { model.history.openProfile(path) }
                .help("What Vogter knows about this program: when it first ran here, its signature, its permissions and alerts")
            if !(model.selectedTab == "history" && model.history.program == path) {
                QuietLink(title: "Everything from this program", symbol: "clock.arrow.circlepath") {
                    model.showInHistory(program: path)
                }
            }
        }
    }

    /// The user's own note and the reviewed mark.
    private var noteCard: some View {
        let saved = event.note ?? ""
        return section("Your note") {
            VStack(alignment: .leading, spacing: 10) {
                TextField("A note for yourself, like “that was me installing PrintStudio”", text: $draft, axis: .vertical)
                    .textFieldStyle(.plain)
                    .font(.system(size: 12.5, design: .rounded))
                    .foregroundStyle(Theme.ink)
                    .lineLimit(2...6)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 8)
                    .background(Theme.cardStrong, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 0.5))
                    .onChange(of: draft) { _, new in
                        if new.count > AppModel.maxNoteLength { draft = String(new.prefix(AppModel.maxNoteLength)) }
                    }
                HStack(spacing: 8) {
                    if draft != saved {
                        Button(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "Remove note" : "Save note") {
                            model.annotate(event, note: draft)
                        }
                        .buttonStyle(SoftButtonStyle(prominent: true))
                    }
                    if let reviewed = event.reviewedAt {
                        Button { model.setReviewed(event, false) } label: {
                            Label("Reviewed", systemImage: "checkmark.circle.fill")
                        }
                        .buttonStyle(SoftButtonStyle())
                        .help("Mark as not reviewed")
                        Text(Date(timeIntervalSince1970: TimeInterval(reviewed)).formatted(date: .abbreviated, time: .shortened))
                            .font(.system(size: 11, design: .rounded)).foregroundStyle(Theme.inkFaint)
                    } else {
                        Button { model.setReviewed(event, true) } label: {
                            Label("Mark reviewed", systemImage: "checkmark.circle")
                        }
                        .buttonStyle(SoftButtonStyle())
                        .help("You've looked at this; the History tab can hide reviewed events")
                    }
                    Spacer(minLength: 0)
                    if draft.count > AppModel.maxNoteLength - 200 {
                        Text("\(draft.count)/\(AppModel.maxNoteLength)")
                            .font(.system(size: 10.5, design: .rounded)).monospacedDigit().foregroundStyle(Theme.inkFaint)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func activityBody(_ a: Activity) -> some View {
        if let advice = a.advice {
            VStack(alignment: .leading, spacing: 6) {
                Label("What this means", systemImage: "leaf")
                    .font(.system(size: 11.5, weight: .semibold, design: .rounded))
                    .foregroundStyle(Theme.moss)
                Text(advice)
                    .font(.system(size: 13, design: .rounded))
                    .foregroundStyle(Theme.ink)
                    .lineSpacing(2)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(14)
            .background {
                RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous).fill(Theme.cardStrong)
                    .overlay(RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous).fill(Theme.adviceWash))
            }
            .overlay(RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous).strokeBorder(Theme.sage.opacity(0.2), lineWidth: 0.5))
        }
        section("Program", accessory: { if let p = a.path { programLinks(p) } }) {
            VStack(alignment: .leading, spacing: 6) {
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
                if let p = a.path { LabeledContent("Location") { MonoBox(text: p) } }
            }
            .font(.system(size: 12.5, design: .rounded))
            .foregroundStyle(Theme.ink)
        }
        if let d = a.detail {
            section("Command and origin") { MonoBox(text: d) }
        }

        HStack(spacing: 8) {
            Menu("Trust…") {
                Button("Trust for this kind of alert") { model.trust(event); trusted = true }
                Button("Trust for all alerts") { model.trust(event, allChecks: true); trusted = true }
            }
            .menuStyle(.button)
            .buttonStyle(SoftButtonStyle(prominent: true))
            .menuIndicator(.visible)
            .fixedSize()
            .help("Stop alerts about this program. Signed apps are trusted by developer; unsigned files by their exact contents.")
            .disabled(trusted)
            if let p = a.path {
                Button("Show in Finder") { model.reveal(path: p) }.buttonStyle(SoftButtonStyle())
            }
            Button("Copy details") { model.copyDetails(event) }.buttonStyle(SoftButtonStyle())
            if let pid = a.pid, model.isRunning(pid: pid, path: a.path) {
                Button("Quit program…", role: .destructive) { confirmQuit = true }
                    .buttonStyle(SoftButtonStyle(destructive: true))
                    .confirmationDialog("Quit \(a.process ?? "this program")?", isPresented: $confirmQuit) {
                        Button("Quit", role: .destructive) { model.terminate(pid: pid) }
                    } message: {
                        Text("Vogter asks it to quit (like Activity Monitor). Unsaved work in it may be lost.")
                    }
            }
        }
        .padding(.top, 2)
        if trusted {
            Label("Trusted. Future alerts about this program are hidden — manage in the Trusted tab.", systemImage: "checkmark.circle")
                .font(.system(size: 11.5, design: .rounded)).foregroundStyle(Theme.moss)
        }
    }

    private func section<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        section(title, accessory: { EmptyView() }, content)
    }

    private func section<Accessory: View, Content: View>(_ title: String, @ViewBuilder accessory: () -> Accessory,
                                                          @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                SectionLabel(title)
                Spacer(minLength: 8)
                accessory()
            }
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .zenCard(padding: 14)
    }
}
