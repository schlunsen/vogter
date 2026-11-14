import AppKit
import Foundation
import Observation
import UniformTypeIdentifiers

/// Everything the History tab shows and asks the daemon for. Owned by `AppModel`,
/// which routes the daemon's history replies here.
@MainActor
@Observable
final class HistoryModel {
    enum Mode: String, CaseIterable, Identifiable {
        case timeline, pastFindings, changes
        var id: String { rawValue }
        var title: String {
            switch self {
            case .timeline: return "Timeline"
            case .pastFindings: return "Past findings"
            case .changes: return "What changed"
            }
        }
    }

    enum SeverityFilter: CaseIterable, Identifiable {
        case all, worthALook, important
        var id: Self { self }
        var title: String {
            switch self {
            case .all: return "All"
            case .worthALook: return "Worth a look"
            case .important: return "Important"
            }
        }
        var minimum: Severity? {
            switch self {
            case .all: return nil
            case .worthALook: return .medium
            case .important: return .high
            }
        }
    }

    /// A kind chip and the daemon `kinds` it stands for (event kinds, activity kinds,
    /// finding categories).
    struct KindChip: Identifiable, Hashable {
        let id: String
        let title: String
        let symbol: String
        let kinds: [String]

        static let all: [KindChip] = [
            KindChip(id: "programs", title: "Programs", symbol: "terminal", kinds: ["process_started"]),
            KindChip(id: "startup", title: "Startup items", symbol: "arrow.clockwise", kinds: ["persistence_changed", "persistence"]),
            KindChip(id: "permissions", title: "Permissions", symbol: "hand.raised", kinds: ["permission_changed", "privacy", "keylogger"]),
            KindChip(id: "sudo", title: "sudo", symbol: "lock.open", kinds: ["sudo"]),
            KindChip(id: "micCamera", title: "Mic & camera", symbol: "mic", kinds: ["microphone_on", "microphone_off", "camera_on", "camera_off"]),
            KindChip(id: "downloads", title: "Downloads", symbol: "arrow.down.circle", kinds: ["download"]),
            KindChip(id: "scans", title: "Scans", symbol: "magnifyingglass", kinds: ["scan_completed", "new_finding", "resolved"]),
        ]
    }

    enum ChangesPreset: CaseIterable, Identifiable {
        case yesterday, week, month
        var id: Self { self }
        var title: String {
            switch self {
            case .yesterday: return "Since yesterday"
            case .week: return "Last week"
            case .month: return "Last month"
            }
        }

        func since(now: Date = Date()) -> UInt64 {
            let cal = Calendar.current
            let today = cal.startOfDay(for: now)
            let date: Date
            switch self {
            case .yesterday: date = cal.date(byAdding: .day, value: -1, to: today) ?? today
            case .week: date = cal.date(byAdding: .day, value: -7, to: today) ?? today
            case .month: date = cal.date(byAdding: .month, value: -1, to: today) ?? today
            }
            return UInt64(date.timeIntervalSince1970)
        }
    }

    enum ExportFormat { case json, csv }

    /// Sends a request to the daemon; nil when offline (screenshots, tests).
    var send: (([String: Any]) -> Void)?

    var mode: Mode = .timeline
    var search = "" {
        didSet { if search != oldValue { scheduleReload() } }
    }
    var severity: SeverityFilter = .all
    var kinds: Set<String> = []
    var program: String?
    var unreviewedOnly = false
    /// Local midnight of the day shown; nil shows all days (searching, following a program).
    var selectedDay: UInt64? = HistoryModel.startOfDay(Date())

    var days: [DaySummary] = []
    var events: [LoggedEvent] = []
    var nextBeforeID: Int64?
    var loading = false
    var away: [AwayPeriod] = []
    var pastFindings: [StoredFinding] = []
    var changes: Changes?
    var changesPreset: ChangesPreset = .week
    /// The program whose profile sheet is open, and its profile once it arrives.
    var profilePath: String?
    var profile: ProgramProfile?
    var selectedEventID: Int64?

    private var token: UInt64 = 0
    private var started = false
    private var searchTask: Task<Void, Never>?

    /// Days the heatmap covers (26 weeks).
    static let heatmapWeeks = 26
    /// Days in the day list.
    static let recentDayCount = 30
    static let pageSize = 100

    var selectedEvent: LoggedEvent? { events.first { $0.id == selectedEventID } }

    var hasFilters: Bool {
        !search.trimmingCharacters(in: .whitespaces).isEmpty || severity != .all || !kinds.isEmpty
            || program != nil || unreviewedOnly
    }

    var programName: String? { program.map { ($0 as NSString).lastPathComponent } }

    // MARK: Loading

    /// First time the tab appears: load the calendar and today.
    func start() {
        guard !started else { return }
        started = true
        refreshDays()
        reload()
    }

    func refreshDays() {
        send?(["type": "history_days", "since": Self.heatmapStart()])
    }

    /// Start over with the current filters.
    func reload() {
        searchTask?.cancel()
        // Offline (screenshots): keep what's there.
        guard let send else { return }
        token += 1
        events = []
        nextBeforeID = nil
        switch mode {
        case .timeline:
            loading = true
            send(query(beforeID: nil))
            var away: [String: Any] = ["type": "away_periods"]
            if let day = selectedDay {
                away["since"] = day
                away["until"] = Self.dayAfter(day)
            } else {
                away["since"] = Self.heatmapStart()
            }
            send(away)
        case .pastFindings:
            var q = filters()
            q["type"] = "finding_history"
            q["resolved_only"] = true
            q["limit"] = 300
            send(q)
        case .changes:
            send(["type": "changes_since", "since": changesPreset.since()])
        }
    }

    /// Next (older) page, for infinite scroll.
    func loadEarlier() {
        guard let next = nextBeforeID, !loading, let send else { return }
        loading = true
        send(query(beforeID: next))
    }

    private func scheduleReload() {
        searchTask?.cancel()
        searchTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard !Task.isCancelled else { return }
            self?.reload()
        }
    }

    private func filters() -> [String: Any] {
        var q: [String: Any] = ["token": token]
        if let min = severity.minimum { q["min_severity"] = min.rawValue }
        let names = KindChip.all.filter { kinds.contains($0.id) }.flatMap(\.kinds)
        if !names.isEmpty { q["kinds"] = names }
        let text = search.trimmingCharacters(in: .whitespaces)
        if !text.isEmpty { q["search"] = text }
        if let program { q["program"] = program }
        return q
    }

    private func query(beforeID: Int64?) -> [String: Any] {
        var q = filters()
        q["type"] = "history"
        q["limit"] = Self.pageSize
        if let day = selectedDay {
            q["since"] = day
            q["until"] = Self.dayAfter(day)
        }
        if let beforeID { q["before_id"] = beforeID }
        if unreviewedOnly { q["unreviewed_only"] = true }
        return q
    }

    func handle(_ msg: DaemonMessage) {
        switch msg {
        case let .history(page, next, tok):
            guard tok == token else { return }
            let known = Set(events.map(\.id))
            events.append(contentsOf: page.filter { !known.contains($0.id) })
            nextBeforeID = next
            loading = false
        case let .historyDays(d): days = d
        case let .findingHistory(f, tok):
            guard tok == token else { return }
            pastFindings = f
        case let .awayPeriods(p): away = p
        case let .programProfile(p):
            if p.path == profilePath { profile = p }
        case let .changes(c): changes = c
        case let .annotation(id, note, reviewedAt): apply(eventID: id, note: note, reviewedAt: reviewedAt)
        default: break
        }
    }

    /// A pushed event: count it for today, and show it if today is on screen unfiltered.
    func didReceive(_ e: LoggedEvent) {
        let today = Self.startOfDay(Date())
        let rank = (e.severity ?? .info).rank
        if let i = days.firstIndex(where: { $0.day == Self.dayString(today) }) {
            days[i].events += 1
            if rank < days[i].counts.count { days[i].counts[rank] += 1 }
        } else {
            var counts: [UInt32] = [0, 0, 0, 0, 0]
            counts[rank] = 1
            days.append(DaySummary(day: Self.dayString(today), start: today, events: 1, counts: counts))
        }
        if mode == .timeline, selectedDay == today, !hasFilters, !events.contains(where: { $0.id == e.id }) {
            events.insert(e, at: 0)
        }
    }

    func apply(eventID: Int64, note: String?, reviewedAt: UInt64?) {
        if let i = events.firstIndex(where: { $0.id == eventID }) {
            events[i].note = note
            events[i].reviewedAt = reviewedAt
        }
        if let i = profile?.events.firstIndex(where: { $0.id == eventID }) {
            profile?.events[i].note = note
            profile?.events[i].reviewedAt = reviewedAt
        }
        if unreviewedOnly, reviewedAt != nil, eventID != selectedEventID {
            events.removeAll { $0.id == eventID }
        }
    }

    // MARK: Actions

    func select(day: UInt64?) {
        selectedDay = day
        selectedEventID = nil
        mode = .timeline
        reload()
    }

    func set(mode: Mode) {
        guard mode != self.mode else { return }
        self.mode = mode
        selectedEventID = nil
        reload()
    }

    /// Everything from one program, across all days.
    func showProgram(_ path: String) {
        program = path
        selectedDay = nil
        selectedEventID = nil
        mode = .timeline
        reload()
    }

    func clearProgram() {
        program = nil
        if selectedDay == nil, !hasFilters { selectedDay = Self.startOfDay(Date()) }
        reload()
    }

    func toggle(kind id: String) {
        if kinds.contains(id) { kinds.remove(id) } else { kinds.insert(id) }
        reload()
    }

    func openProfile(_ path: String) {
        profilePath = path
        profile = nil
        send?(["type": "program_profile", "path": path])
    }

    // MARK: Days

    struct DayRow: Identifiable, Hashable {
        let start: UInt64
        let summary: DaySummary?
        var id: UInt64 { start }
        var date: Date { Date(timeIntervalSince1970: TimeInterval(start)) }
        var events: UInt32 { summary?.events ?? 0 }
        var toLookAt: UInt32 { (summary?.worthALook ?? 0) + (summary?.important ?? 0) }

        var title: String {
            let cal = Calendar.current
            if cal.isDateInToday(date) { return "Today" }
            if cal.isDateInYesterday(date) { return "Yesterday" }
            return date.formatted(.dateTime.weekday(.wide).day().month(.abbreviated))
        }

        /// "2 to look at", "all calm", "quiet".
        var mood: String {
            if toLookAt > 0 { return "\(toLookAt) to look at" }
            return events > 0 ? "all calm" : "quiet"
        }
    }

    /// The last `recentDayCount` days, newest first, including quiet ones.
    func recentDays(now: Date = Date()) -> [DayRow] {
        let byDay = Dictionary(days.map { ($0.day, $0) }, uniquingKeysWith: { a, _ in a })
        let cal = Calendar.current
        let today = cal.startOfDay(for: now)
        return (0..<Self.recentDayCount).compactMap { offset in
            guard let d = cal.date(byAdding: .day, value: -offset, to: today) else { return nil }
            let start = UInt64(d.timeIntervalSince1970)
            return DayRow(start: start, summary: byDay[Self.dayString(start)])
        }
    }

    func summary(for start: UInt64) -> DaySummary? {
        days.first { $0.day == Self.dayString(start) }
    }

    /// Calendar heatmap columns (weeks, oldest first), each with 7 days; nil for days
    /// still to come.
    func heatmap(now: Date = Date()) -> [[DayRow?]] {
        let byDay = Dictionary(days.map { ($0.day, $0) }, uniquingKeysWith: { a, _ in a })
        let cal = Calendar.current
        let today = cal.startOfDay(for: now)
        guard let thisWeek = cal.dateInterval(of: .weekOfYear, for: today)?.start,
              let first = cal.date(byAdding: .weekOfYear, value: -(Self.heatmapWeeks - 1), to: thisWeek)
        else { return [] }
        return (0..<Self.heatmapWeeks).map { week in
            (0..<7).map { weekday in
                guard let d = cal.date(byAdding: .day, value: week * 7 + weekday, to: first), d <= today else { return nil }
                let start = UInt64(d.timeIntervalSince1970)
                return DayRow(start: start, summary: byDay[Self.dayString(start)])
            }
        }
    }

    static func heatmapStart(now: Date = Date()) -> UInt64 {
        let cal = Calendar.current
        let today = cal.startOfDay(for: now)
        let start = cal.date(byAdding: .day, value: -(heatmapWeeks * 7 + 7), to: today) ?? today
        return UInt64(start.timeIntervalSince1970)
    }

    static func startOfDay(_ date: Date) -> UInt64 {
        UInt64(Calendar.current.startOfDay(for: date).timeIntervalSince1970)
    }

    static func dayAfter(_ start: UInt64) -> UInt64 {
        let d = Date(timeIntervalSince1970: TimeInterval(start))
        let next = Calendar.current.date(byAdding: .day, value: 1, to: d) ?? d.addingTimeInterval(86_400)
        return UInt64(next.timeIntervalSince1970)
    }

    private static let dayFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.calendar = Calendar(identifier: .gregorian)
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    /// The daemon's `DaySummary.day` for a local midnight.
    static func dayString(_ start: UInt64) -> String {
        dayFormatter.timeZone = .current
        return dayFormatter.string(from: Date(timeIntervalSince1970: TimeInterval(start)))
    }

    // MARK: Timeline

    struct Section: Identifiable, Hashable {
        enum Kind: Hashable {
            case hour(UInt64)
            case away(AwayPeriod)
        }

        var kind: Kind
        var events: [LoggedEvent]
        /// First section of a new day (shown in the all-days view).
        var day: UInt64?

        var id: String {
            switch kind {
            case let .hour(h): return "h\(h)"
            case let .away(p): return "a\(p.from)"
            }
        }

        var top: UInt64 {
            switch kind {
            case let .hour(h): return events.first?.at ?? h
            case let .away(p): return p.until ?? UInt64(Date().timeIntervalSince1970)
            }
        }
    }

    /// Events (newest first) grouped by hour, with time away as its own band. Lock and
    /// unlock events are folded into their band. Bands without events are shown only
    /// when nothing is filtered, so a calm afternoon away still shows up.
    static func sections(events: [LoggedEvent], away: [AwayPeriod], showEmptyAway: Bool,
                         range: (since: UInt64, until: UInt64)? = nil) -> [Section] {
        let cal = Calendar.current
        var out: [Section] = []
        var used = Set<UInt64>()
        for e in events {
            let band = away.first { $0.from <= e.at && e.at <= ($0.until ?? .max) }
            let kind: Section.Kind
            if let band {
                kind = .away(band)
                used.insert(band.from)
            } else {
                let hour = cal.dateInterval(of: .hour, for: Date(timeIntervalSince1970: TimeInterval(e.at)))?.start
                kind = .hour(UInt64(hour?.timeIntervalSince1970 ?? TimeInterval(e.at)))
            }
            let folded: Bool = {
                guard band != nil, case let .activity(a) = e.kind else { return false }
                return a.kind == "screen_locked" || a.kind == "screen_unlocked"
            }()
            if out.last?.kind == kind {
                if !folded { out[out.count - 1].events.append(e) }
            } else {
                out.append(Section(kind: kind, events: folded ? [] : [e]))
            }
        }
        if showEmptyAway {
            for band in away where !used.contains(band.from) {
                if let range, !(band.from < range.until && (band.until ?? .max) > range.since) { continue }
                let s = Section(kind: .away(band), events: [])
                let i = out.firstIndex { $0.top < s.top } ?? out.count
                out.insert(s, at: i)
            }
        }
        var lastDay: UInt64?
        for i in out.indices {
            let day = startOfDay(Date(timeIntervalSince1970: TimeInterval(out[i].top)))
            if day != lastDay { out[i].day = day }
            lastDay = day
        }
        return out
    }

    // MARK: Export

    /// The visible history (redacted, as the daemon sends it) as JSON or CSV.
    static func exportData(events: [LoggedEvent], format: ExportFormat) -> Data {
        let iso = ISO8601DateFormatter()
        iso.timeZone = .current
        let rows: [[String: Any]] = events.map { e in
            var row: [String: Any] = [
                "id": e.id,
                "time": iso.string(from: Date(timeIntervalSince1970: TimeInterval(e.at))),
                "kind": e.kindNames.last ?? "",
                "summary": e.text,
            ]
            if let s = e.severity { row["severity"] = s.rawValue }
            if case let .activity(a) = e.kind {
                row["detail"] = a.detail
                row["process"] = a.process
                row["path"] = a.path
            } else if case let .newFinding(f) = e.kind {
                row["detail"] = f.detail
                row["path"] = f.path
            }
            row["note"] = e.note
            if let r = e.reviewedAt { row["reviewed"] = iso.string(from: Date(timeIntervalSince1970: TimeInterval(r))) }
            return row
        }
        switch format {
        case .json:
            return (try? JSONSerialization.data(withJSONObject: rows, options: [.prettyPrinted, .sortedKeys])) ?? Data()
        case .csv:
            let columns = ["id", "time", "severity", "kind", "summary", "detail", "process", "path", "note", "reviewed"]
            func cell(_ v: Any?) -> String {
                guard let v else { return "" }
                let s = "\(v)"
                guard s.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" || $0 == "\r" }) else { return s }
                return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\""
            }
            let lines = [columns.joined(separator: ",")] + rows.map { r in columns.map { cell(r[$0]) }.joined(separator: ",") }
            return Data((lines.joined(separator: "\r\n") + "\r\n").utf8)
        }
    }

    func export(_ format: ExportFormat) {
        let panel = NSSavePanel()
        let stamp = Date().formatted(.iso8601.year().month().day())
        panel.nameFieldStringValue = "Vogter history \(stamp).\(format == .json ? "json" : "csv")"
        panel.allowedContentTypes = [format == .json ? .json : .commaSeparatedText]
        panel.message = "Exports the history shown, as Vogter recorded it (secrets already removed)."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try Self.exportData(events: events, format: format).write(to: url, options: .atomic)
        } catch {
            NSAlert(error: error).runModal()
        }
    }
}
