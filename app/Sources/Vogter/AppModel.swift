import AppKit
import Foundation
import Observation

@MainActor
@Observable
final class AppModel {
    var connected = false
    var socketPath: String?
    var status: DaemonStatus?
    var findings: [StoredFinding] = []
    var events: [LoggedEvent] = []
    var trustRules: [TrustRule] = []
    /// Main window state, so alerts can open it on the right item.
    var selectedTab = "findings"
    var selectedEventID: Int64?

    var selectedEvent: LoggedEvent? {
        events.first { $0.id == selectedEventID }
    }

    /// Show an alert in the main window (the caller opens the window).
    func select(eventID: Int64) {
        selectedTab = "activity"
        selectedEventID = eventID
        if !events.contains(where: { $0.id == eventID }) {
            connection?.send(["type": "events", "limit": 500])
        }
    }
    var lastError: String?

    var showInfo: Bool = UserDefaults.standard.bool(forKey: "showInfo") {
        didSet { UserDefaults.standard.set(showInfo, forKey: "showInfo") }
    }

    private var connection: DaemonConnection?
    private var pollTimer: Timer?
    private var retryTimer: Timer?
    /// Nil when not connecting (screenshot mode): creating one touches the notification center.
    private let notifier: Notifier?
    /// When set, `isRunning` answers from this instead of the real process table (screenshot mode).
    var simulatedRunningPIDs: Set<Int32>?

    /// `connect: false` builds an empty, offline model that never talks to vogterd or
    /// asks for notification permission (used to render screenshots from demo data).
    init(connect: Bool = true) {
        guard connect else {
            notifier = nil
            return
        }
        notifier = Notifier()
        notifier?.requestAuthorization()
        self.connect()
        // Status carries live mic/camera state and counts; keep it fresh.
        pollTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.connection?.send(["type": "status"]) }
        }
    }

    var visibleFindings: [StoredFinding] {
        findings.filter { showInfo || $0.severity > .info }
    }

    /// Medium-or-worse activity from the last 24 hours, newest first.
    var recentAlerts: [LoggedEvent] {
        let since = UInt64(Date().timeIntervalSince1970) - 86_400
        return events.filter { e in
            guard e.at >= since, let sev = e.severity, sev >= .medium, case .activity = e.kind else { return false }
            return true
        }
    }

    /// Highest severity among open findings, ignoring info.
    var worst: Severity? {
        findings.map(\.severity).filter { $0 > .info }.max()
    }

    var menuBarSymbol: String {
        // Calm: a leaf. Needs a look: a shield that says so. Not connected: resting.
        guard connected else { return "moon.zzz" }
        switch worst {
        case .critical?, .high?: return "exclamationmark.shield.fill"
        case .medium?: return "exclamationmark.shield"
        default: return "leaf"
        }
    }

    // MARK: Actions

    func scanNow() { connection?.send(["type": "scan_now"]) ; refreshSoon() }

    func acknowledge(_ f: StoredFinding) {
        connection?.send(["type": "acknowledge", "key": f.key])
        findings.removeAll { $0.key == f.key }
        connection?.send(["type": "status"])
    }

    func trust(_ f: StoredFinding, allChecks: Bool = false) {
        connection?.send(["type": "trust", "finding_key": f.key, "all_checks": allChecks])
        findings.removeAll { $0.key == f.key }
    }

    func trust(_ e: LoggedEvent, allChecks: Bool = false) {
        connection?.send(["type": "trust", "event_id": e.id, "all_checks": allChecks])
    }

    func untrust(_ r: TrustRule) {
        connection?.send(["type": "untrust", "id": r.id])
        trustRules.removeAll { $0.id == r.id }
        refreshSoon()
    }

    func reveal(path: String) {
        NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
    }

    func copyDetails(_ e: LoggedEvent) {
        guard case let .activity(a) = e.kind else { return }
        var lines = ["[\(a.severity.label)] \(a.summary)", "Time: \(Date(timeIntervalSince1970: TimeInterval(e.at)))"]
        if let p = a.process { lines.append("Program: \(p)\(a.pid.map { " (pid \($0))" } ?? "")") }
        if let p = a.path { lines.append("Path: \(p)") }
        if let s = a.signing { lines.append("Signature: \(s.summary)\(s.identifier.map { " [\($0)]" } ?? "")") }
        if let d = a.detail { lines.append("Details: \(d)") }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(lines.joined(separator: "\n"), forType: .string)
    }

    /// Whether `pid` is still the program at `path` (PIDs get reused).
    func isRunning(pid: Int32, path: String?) -> Bool {
        if let simulated = simulatedRunningPIDs { return simulated.contains(pid) }
        guard kill(pid, 0) == 0 || errno == EPERM else { return false }
        guard let path else { return true }
        var buf = [CChar](repeating: 0, count: 4096)
        guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { return false }
        return String(cString: buf) == path
    }

    /// Ask the program to quit (SIGTERM). Returns false if not allowed (e.g. another user's process).
    @discardableResult
    func terminate(pid: Int32) -> Bool {
        kill(pid, SIGTERM) == 0
    }

    func reveal(_ f: StoredFinding) {
        guard let path = f.path else { return }
        NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
    }

    func refresh() {
        connection?.send(["type": "status"])
        connection?.send(["type": "findings"])
        connection?.send(["type": "events", "limit": 200])
        connection?.send(["type": "trust_rules"])
    }

    // MARK: Connection

    private func connect() {
        retryTimer?.invalidate()
        guard let (conn, path) = DaemonConnection.connectAny() else {
            connected = false
            scheduleRetry()
            return
        }
        connection = conn
        socketPath = path
        connected = true
        lastError = nil
        conn.start(
            onMessage: { [weak self] msg in self?.handle(msg) },
            onClose: { [weak self] in self?.disconnected() })
        conn.send(["type": "subscribe"])
        refresh()
    }

    private func disconnected() {
        connection = nil
        connected = false
        status = nil
        scheduleRetry()
    }

    private func scheduleRetry() {
        retryTimer?.invalidate()
        retryTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: false) { [weak self] _ in
            Task { @MainActor in self?.connect() }
        }
    }

    private func refreshSoon() {
        Timer.scheduledTimer(withTimeInterval: 2, repeats: false) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    private func handle(_ msg: DaemonMessage) {
        switch msg {
        case let .status(s): status = s
        case let .findings(f): findings = f
        case let .events(e): events = e
        case let .trustRules(r): trustRules = r
        case .trusted:
            connection?.send(["type": "trust_rules"])
            connection?.send(["type": "status"])
        case let .error(m): lastError = m
        case let .event(e):
            events.insert(e, at: 0)
            if events.count > 500 { events.removeLast(events.count - 500) }
            notifier?.notify(for: e)
            switch e.kind {
            case .scanCompleted, .newFinding, .resolved:
                connection?.send(["type": "findings"])
                connection?.send(["type": "status"])
            default:
                connection?.send(["type": "status"])
            }
        case .ok, .unknown: break
        }
    }
}
