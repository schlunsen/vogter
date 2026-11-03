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
    var lastError: String?

    var showInfo: Bool = UserDefaults.standard.bool(forKey: "showInfo") {
        didSet { UserDefaults.standard.set(showInfo, forKey: "showInfo") }
    }

    private var connection: DaemonConnection?
    private var pollTimer: Timer?
    private var retryTimer: Timer?
    private let notifier = Notifier()

    init() {
        notifier.requestAuthorization()
        connect()
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
        guard connected else { return "shield.slash" }
        switch worst {
        case .critical?, .high?: return "exclamationmark.shield.fill"
        case .medium?: return "exclamationmark.shield"
        default: return "checkmark.shield"
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
            notifier.notify(for: e)
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
