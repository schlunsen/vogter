import SwiftUI

/// Looking back: a calendar of calm and busy days, each day's timeline, findings that
/// came and went, and what changed since a moment.
struct HistoryTab: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let h = model.history
        HStack(alignment: .top, spacing: 18) {
            HistorySidebar()
                .frame(width: 262)
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 10) {
                    ZenSegmented(options: HistoryModel.Mode.allCases.map { ($0, $0.title) }, selection: h.mode) { h.set(mode: $0) }
                    Spacer()
                    if h.mode == .timeline {
                        Menu {
                            Button("As JSON…") { h.export(.json) }
                            Button("As CSV…") { h.export(.csv) }
                        } label: {
                            Label("Export", systemImage: "square.and.arrow.up")
                        }
                        .menuStyle(.button)
                        .buttonStyle(SoftButtonStyle())
                        .menuIndicator(.hidden)
                        .fixedSize()
                        .disabled(h.events.isEmpty)
                        .help("Save the history shown here as a file (secrets are already removed)")
                    }
                }
                if !model.connected {
                    NotRunningView().zenCard(padding: 18).frame(maxWidth: 420, alignment: .leading)
                    Spacer()
                } else {
                    switch h.mode {
                    case .timeline:
                        if let e = h.selectedEvent {
                            VStack(alignment: .leading, spacing: 8) {
                                QuietLink(title: "Back to the timeline", symbol: "chevron.left") { h.selectedEventID = nil }
                                    .padding(.leading, 4)
                                EventDetail(event: e).id(e.id)
                            }
                        } else {
                            HistoryFilterBar()
                            HistoryTimeline()
                        }
                    case .pastFindings:
                        HistoryFilterBar(showsReviewed: false)
                        PastFindingsList()
                    case .changes:
                        ChangesView()
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(minHeight: 0, maxHeight: .infinity, alignment: .top)
        .onAppear { h.start() }
    }
}

// MARK: Sidebar: heatmap and recent days

private struct HistorySidebar: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let h = model.history
        VStack(alignment: .leading, spacing: 12) {
            HistoryHeatmap()
                .zenCard(padding: 12)
            SectionLabel("Recent days").padding(.leading, 4)
            ScrollView {
                LazyVStack(spacing: 4) {
                    ForEach(h.recentDays()) { day in
                        DayRowView(day: day, selected: h.selectedDay == day.start) {
                            h.select(day: day.start)
                        }
                    }
                }
                .padding(4)
            }
            .padding(-4)
            .frame(minHeight: 0, maxHeight: .infinity)
        }
        .frame(maxHeight: .infinity, alignment: .top)
    }
}

private struct DayRowView: View {
    let day: HistoryModel.DayRow
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 1) {
                    Text(day.title)
                        .font(.system(size: 12.5, weight: selected ? .semibold : .medium, design: .rounded))
                        .foregroundStyle(Theme.ink)
                    Text(day.mood)
                        .font(.system(size: 11, design: .rounded))
                        .foregroundStyle(day.toLookAt > 0 ? (day.summary?.important ?? 0 > 0 ? Severity.high.ink : Severity.medium.ink) : Theme.inkFaint)
                }
                Spacer(minLength: 6)
                VStack(alignment: .trailing, spacing: 4) {
                    DayMoodBar(summary: day.summary, width: 36)
                    if day.events > 0 {
                        Text("\(day.events)")
                            .font(.system(size: 10.5, design: .rounded)).monospacedDigit()
                            .foregroundStyle(Theme.inkFaint)
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .background {
                let shape = RoundedRectangle(cornerRadius: 11, style: .continuous)
                if selected {
                    shape.fill(Theme.cardStrong).overlay(shape.fill(Theme.calmSoft))
                        .overlay(shape.strokeBorder(Theme.sage.opacity(0.28), lineWidth: 0.5))
                        .shadow(color: Theme.shadow, radius: 3, y: 1)
                } else {
                    shape.fill(Theme.card.opacity(0.6))
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// Six months at a glance: weeks as columns, days as cells.
private struct HistoryHeatmap: View {
    @Environment(AppModel.self) private var model
    @State private var hovered: HistoryModel.DayRow?

    var body: some View {
        let h = model.history
        let weeks = h.heatmap()
        let gap: CGFloat = 2
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Six months").font(.system(size: 11.5, weight: .semibold, design: .rounded)).foregroundStyle(Theme.inkFaint)
                Spacer()
                Text(caption)
                    .font(.system(size: 10.5, design: .rounded)).foregroundStyle(Theme.inkFaint)
                    .lineLimit(1)
            }
            GeometryReader { geo in
                let cell = max(4, (geo.size.width - gap * CGFloat(weeks.count - 1)) / CGFloat(max(weeks.count, 1)))
                VStack(alignment: .leading, spacing: 4) {
                    HStack(alignment: .top, spacing: gap) {
                        ForEach(Array(weeks.enumerated()), id: \.offset) { _, week in
                            VStack(spacing: gap) {
                                ForEach(0..<7, id: \.self) { i in
                                    if let day = week[i] {
                                        let selected = h.selectedDay == day.start
                                        RoundedRectangle(cornerRadius: 2, style: .continuous)
                                            .fill(heatColor(day.summary))
                                            .overlay(RoundedRectangle(cornerRadius: 2, style: .continuous)
                                                .strokeBorder(selected ? Theme.ink.opacity(0.55) : .clear, lineWidth: 1))
                                            .frame(width: cell, height: cell)
                                            .contentShape(Rectangle())
                                            .onTapGesture { h.select(day: day.start) }
                                            .onHover { inside in hovered = inside ? day : (hovered == day ? nil : hovered) }
                                            .help("\(day.title) · \(day.mood)")
                                    } else {
                                        Color.clear.frame(width: cell, height: cell)
                                    }
                                }
                            }
                        }
                    }
                    HStack(spacing: 0) {
                        ForEach(monthLabels(weeks), id: \.offset) { label in
                            Text(label.title)
                                .font(.system(size: 9.5, design: .rounded))
                                .foregroundStyle(Theme.inkFaint)
                                .fixedSize()
                                .frame(width: (cell + gap) * CGFloat(label.span), alignment: .leading)
                        }
                    }
                }
            }
            .frame(height: heatmapHeight)
        }
    }

    private var heatmapHeight: CGFloat {
        // 26 columns in ~238pt: ~7.3pt cells, 7 rows plus month labels.
        let cell = (238 - 2 * 25) / 26.0
        return cell * 7 + 2 * 6 + 4 + 12
    }

    private var caption: String {
        if let d = hovered { return "\(d.title) · \(d.mood)" }
        let days = model.history.heatmap().flatMap { $0 }.compactMap { $0 }
        let calm = days.filter { $0.events > 0 && $0.toLookAt == 0 }.count
        let looked = days.filter { $0.toLookAt > 0 }.count
        return looked == 0 ? "all calm" : "\(calm) calm days · \(looked) to look at"
    }

    /// Month names over the first week that starts in that month.
    private func monthLabels(_ weeks: [[HistoryModel.DayRow?]]) -> [(offset: Int, title: String, span: Int)] {
        var out: [(offset: Int, title: String, span: Int)] = []
        let cal = Calendar.current
        var lastMonth: Int?
        for (i, week) in weeks.enumerated() {
            guard let first = week.compactMap({ $0 }).first else { continue }
            let month = cal.component(.month, from: first.date)
            if month != lastMonth {
                let title = lastMonth == nil && cal.component(.day, from: first.date) > 7 ? "" : first.date.formatted(.dateTime.month(.abbreviated))
                out.append((i, title, 1))
                lastMonth = month
            } else if !out.isEmpty {
                out[out.count - 1].span += 1
            }
        }
        return out
    }
}

// MARK: Filters

private struct HistoryFilterBar: View {
    @Environment(AppModel.self) private var model
    var showsReviewed = true

    var body: some View {
        @Bindable var h = model.history
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                ZenSearchField(prompt: "Search history", text: $h.search)
                    .frame(width: 190)
                    .padding(.trailing, 4)
                ForEach(HistoryModel.SeverityFilter.allCases) { s in
                    ZenChip(title: s.title, selected: h.severity == s) { h.severity = s; h.reload() }
                }
                Spacer(minLength: 0)
                if showsReviewed {
                    ZenChip(title: "Unreviewed", symbol: "circle.dashed", selected: h.unreviewedOnly) {
                        h.unreviewedOnly.toggle(); h.reload()
                    }
                    .help("Hide events you've marked reviewed")
                }
            }
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(HistoryModel.KindChip.all) { k in
                        ZenChip(title: k.title, symbol: k.symbol, selected: h.kinds.contains(k.id)) { h.toggle(kind: k.id) }
                    }
                }
                .padding(.vertical, 1)
            }
            if let name = h.programName, let path = h.program {
                HStack(spacing: 8) {
                    Image(systemName: "line.3.horizontal.decrease.circle").foregroundStyle(Theme.moss)
                    Text("Only \(name)").font(.system(size: 12, weight: .medium, design: .rounded)).foregroundStyle(Theme.ink)
                    QuietLink(title: "Who is this?", symbol: "person.text.rectangle") { h.openProfile(path) }
                    Spacer()
                    Button { h.clearProgram() } label: {
                        Image(systemName: "xmark").font(.system(size: 10, weight: .semibold)).foregroundStyle(Theme.inkSoft)
                    }
                    .buttonStyle(.plain)
                    .help("Show everything again")
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(Theme.sage.opacity(0.10), in: Capsule(style: .continuous))
                .overlay(Capsule(style: .continuous).strokeBorder(Theme.sage.opacity(0.22), lineWidth: 0.5))
            }
        }
    }
}

// MARK: Timeline

private struct HistoryTimeline: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let h = model.history
        let range = h.selectedDay.map { (since: $0, until: HistoryModel.dayAfter($0)) }
        let sections = HistoryModel.sections(events: h.events, away: h.away, showEmptyAway: !h.hasFilters, range: range)
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 12) {
                header
                if sections.isEmpty, !h.loading {
                    CalmEmptyState(symbol: "leaf", title: h.hasFilters ? "Nothing matches" : "A quiet day",
                                   message: h.hasFilters ? "Try fewer filters, or look at all days."
                                       : "Vogter didn't note anything on this day.")
                        .frame(height: 260)
                }
                ForEach(sections) { s in
                    if h.selectedDay == nil, let day = s.day {
                        Text(HistoryModel.DayRow(start: day, summary: nil).title)
                            .font(.system(size: 13, weight: .semibold, design: .rounded))
                            .foregroundStyle(Theme.ink)
                            .padding(.top, 6).padding(.leading, 4)
                    }
                    switch s.kind {
                    case let .hour(hour): HourBlock(hour: hour, events: s.events)
                    case let .away(period): AwayBand(period: period, events: s.events)
                    }
                }
                footer
            }
            .padding(8)
        }
        .padding(-8)
    }

    private var header: some View {
        let h = model.history
        return HStack(alignment: .firstTextBaseline, spacing: 8) {
            if let day = h.selectedDay {
                let row = HistoryModel.DayRow(start: day, summary: h.summary(for: day))
                Text(row.title).font(.system(size: 17, weight: .semibold, design: .rounded)).foregroundStyle(Theme.ink)
                Text(row.date.formatted(.dateTime.weekday(.wide).day().month(.wide)))
                    .font(.system(size: 12, design: .rounded)).foregroundStyle(Theme.inkFaint)
                    .opacity(row.title == "Today" || row.title == "Yesterday" ? 1 : 0)
                Spacer()
                Text(dayMood(row)).font(.system(size: 12, design: .rounded)).foregroundStyle(Theme.inkSoft)
                if h.hasFilters {
                    QuietLink(title: "All days", symbol: "calendar") { h.select(day: nil) }
                }
            } else {
                Text("All days").font(.system(size: 17, weight: .semibold, design: .rounded)).foregroundStyle(Theme.ink)
                Spacer()
                QuietLink(title: "Back to today", symbol: "sun.max") { h.select(day: HistoryModel.startOfDay(Date())) }
            }
        }
        .padding(.horizontal, 4)
    }

    private func dayMood(_ row: HistoryModel.DayRow) -> String {
        guard row.events > 0 else { return "Nothing noted" }
        let events = "\(row.events) event\(row.events == 1 ? "" : "s")"
        if row.toLookAt > 0 { return "\(row.toLookAt) to look at · \(events)" }
        return "All calm · \(events)"
    }

    @ViewBuilder
    private var footer: some View {
        let h = model.history
        if h.nextBeforeID != nil {
            HStack {
                Spacer()
                Button(h.loading ? "Loading…" : "Load earlier") { h.loadEarlier() }
                    .buttonStyle(SoftButtonStyle())
                    .disabled(h.loading)
                Spacer()
            }
            .onAppear { h.loadEarlier() }
            .padding(.vertical, 6)
        } else if !h.events.isEmpty {
            Text(h.selectedDay == nil ? "That's everything Vogter remembers." : "That's the whole day.")
                .font(.system(size: 11, design: .rounded)).foregroundStyle(Theme.inkFaint)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
        }
    }
}

private struct HourBlock: View {
    let hour: UInt64
    let events: [LoggedEvent]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(timeText(hour)).font(.system(size: 11, weight: .semibold, design: .rounded)).foregroundStyle(Theme.inkFaint)
                .monospacedDigit()
                .padding(.leading, 6)
            VStack(spacing: 0) {
                ForEach(Array(events.enumerated()), id: \.element.id) { i, e in
                    if i > 0 { Divider().overlay(Theme.hairline).padding(.leading, 40) }
                    TimelineRow(event: e)
                }
            }
            .zenCard(padding: 4)
        }
    }
}

/// Time away, as a soft dusk-tinted band holding what happened meanwhile.
private struct AwayBand: View {
    let period: AwayPeriod
    let events: [LoggedEvent]

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous)
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "moon.stars").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.dusk)
                Text(title).font(.system(size: 12, weight: .semibold, design: .rounded)).foregroundStyle(Theme.ink)
                Spacer()
                Text(span).font(.system(size: 11, design: .rounded)).monospacedDigit().foregroundStyle(Theme.inkFaint)
            }
            .padding(.horizontal, 8)
            .padding(.top, 2)
            if events.isEmpty {
                Text("Nothing happened.").font(.system(size: 11.5, design: .rounded)).foregroundStyle(Theme.inkSoft)
                    .padding(.horizontal, 8).padding(.bottom, 2)
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(events.enumerated()), id: \.element.id) { i, e in
                        if i > 0 { Divider().overlay(Theme.hairline).padding(.leading, 40) }
                        TimelineRow(event: e)
                    }
                }
                .padding(4)
                .background(Theme.card, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
            }
        }
        .padding(8)
        .background(shape.fill(LinearGradient(colors: [Theme.dusk.opacity(0.10), Theme.mist.opacity(0.07)],
                                              startPoint: .topLeading, endPoint: .bottomTrailing)))
        .overlay(shape.strokeBorder(Theme.dusk.opacity(0.18), lineWidth: 0.5))
    }

    private var title: String {
        guard let until = period.until else { return "Away since \(timeText(period.from))" }
        return "While you were away · \(durationText(until - period.from))"
    }

    private var span: String {
        guard let until = period.until else { return "" }
        return "\(timeText(period.from)) – \(timeText(until))"
    }
}

private struct TimelineRow: View {
    @Environment(AppModel.self) private var model
    let event: LoggedEvent

    var body: some View {
        Button { model.history.selectedEventID = event.id } label: {
            HStack(alignment: .top, spacing: 10) {
                Squircle(symbol: event.symbol, tint: event.severity.map(\.color) ?? Theme.inkFaint, size: 22)
                Text(event.text)
                    .font(.system(size: 12.5, design: .rounded))
                    .foregroundStyle(Theme.ink)
                    .lineLimit(2)
                    .multilineTextAlignment(.leading)
                    .padding(.top, 2)
                Spacer(minLength: 6)
                if event.note != nil {
                    Image(systemName: "note.text").font(.system(size: 11)).foregroundStyle(Theme.moss)
                        .padding(.top, 4).help(event.note ?? "")
                }
                if event.reviewedAt != nil {
                    Image(systemName: "checkmark.circle").font(.system(size: 11)).foregroundStyle(Theme.sage)
                        .padding(.top, 4).help("Reviewed")
                }
                if let sev = event.severity, sev > .info { SeverityBadge(severity: sev).padding(.top, 1) }
                Text(timeText(event.at))
                    .font(.system(size: 11, design: .rounded)).monospacedDigit()
                    .foregroundStyle(Theme.inkFaint)
                    .padding(.top, 3)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

// MARK: Past findings

private struct PastFindingsList: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let h = model.history
        let items = h.pastFindings.filter { model.showInfo || $0.severity > .info }
        if items.isEmpty {
            CalmEmptyState(symbol: "leaf", title: "No past findings",
                           message: "Findings that came and went are listed here, with when they appeared and when they left.")
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 10) {
                    ForEach(items) { f in PastFindingRow(finding: f).zenCard(padding: 14) }
                }
                .padding(8)
            }
            .padding(-8)
        }
    }
}

struct PastFindingRow: View {
    @Environment(AppModel.self) private var model
    let finding: StoredFinding

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Squircle(symbol: finding.symbol, tint: finding.severity.color.opacity(0.8), size: 28)
            VStack(alignment: .leading, spacing: 3) {
                Text(finding.title).font(.system(size: 13, weight: .medium, design: .rounded)).foregroundStyle(Theme.ink)
                Text(finding.detail).font(.system(size: 11.5)).foregroundStyle(Theme.inkSoft).lineLimit(2).textSelection(.enabled)
                HStack(spacing: 6) {
                    SeverityBadge(severity: finding.severity)
                    Text(span).font(.system(size: 10.5, design: .rounded)).foregroundStyle(Theme.inkFaint)
                }
                .padding(.top, 2)
            }
            Spacer(minLength: 4)
            if let path = finding.path {
                QuietLink(title: "Who is this?", symbol: "person.text.rectangle") { model.history.openProfile(path) }
                    .padding(.top, 2)
            }
        }
        .padding(.vertical, 2)
    }

    private var span: String {
        let first = "First seen \(dateText(finding.firstSeen))"
        guard let gone = finding.resolvedAt else { return "\(first) · still here" }
        let days = (gone - finding.firstSeen) / 86_400
        let lasted = days == 0 ? "less than a day" : "\(days) day\(days == 1 ? "" : "s")"
        return "\(first) → gone \(dateText(gone)) · \(lasted)"
    }
}

// MARK: What changed

/// The groups "What changed" sorts findings into, by category.
struct ChangeGroup: Identifiable {
    let id: String
    let title: String
    let symbol: String
    let noun: (singular: String, plural: String)
    let categories: Set<String>

    static let all: [ChangeGroup] = [
        ChangeGroup(id: "startup", title: "Startup items", symbol: "arrow.clockwise", noun: ("startup item", "startup items"), categories: ["persistence"]),
        ChangeGroup(id: "permissions", title: "Permissions and keyboard", symbol: "hand.raised", noun: ("permission", "permissions"), categories: ["privacy", "keylogger"]),
        ChangeGroup(id: "programs", title: "Programs", symbol: "terminal", noun: ("program", "programs"), categories: ["process"]),
        ChangeGroup(id: "extensions", title: "Browser extensions", symbol: "puzzlepiece.extension", noun: ("extension", "extensions"), categories: ["browser"]),
        ChangeGroup(id: "network", title: "Network", symbol: "network", noun: ("listener", "listeners"), categories: ["network"]),
        ChangeGroup(id: "health", title: "Protections", symbol: "heart", noun: ("protection change", "protection changes"), categories: ["system_health"]),
    ]

    static func of(_ f: StoredFinding) -> ChangeGroup {
        all.first { $0.categories.contains(f.category) }
            ?? ChangeGroup(id: "other", title: "Other", symbol: "sparkle", noun: ("other change", "other changes"), categories: [])
    }

    /// "Since last Tuesday: 2 new startup items, 1 new permission, 1 went away".
    static func summary(_ c: Changes, since: String, showInfo: Bool) -> String {
        let keep = { (f: StoredFinding) in showInfo || f.severity > .info }
        let new = c.newFindings.filter(keep)
        let gone = c.resolvedFindings.filter(keep)
        var parts: [String] = []
        for g in all + [of(StoredFinding.placeholder)] {
            var n = new.filter { of($0).id == g.id }.count
            if g.id == "programs" { n += c.newPrograms.count }
            if n > 0 { parts.append("\(n) new \(n == 1 ? g.noun.singular : g.noun.plural)") }
        }
        if !gone.isEmpty { parts.append("\(gone.count) went away") }
        return parts.isEmpty ? "\(since): nothing changed. All calm." : "\(since): \(parts.joined(separator: ", "))"
    }
}

private extension StoredFinding {
    static let placeholder = StoredFinding(key: "", severity: .info, category: "", check: "", title: "", detail: "",
                                           firstSeen: 0, lastSeen: 0, acknowledged: false)
}

private struct ChangesView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let h = model.history
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 6) {
                ForEach(HistoryModel.ChangesPreset.allCases) { p in
                    ZenChip(title: p.title, selected: h.changesPreset == p) { h.changesPreset = p; h.reload() }
                }
            }
            if let c = h.changes {
                content(c)
            }
            Spacer(minLength: 0)
        }
        .frame(minHeight: 0, maxHeight: .infinity, alignment: .top)
    }

    private var sinceText: String {
        let h = model.history
        switch h.changesPreset {
        case .yesterday: return "Since yesterday"
        case .week:
            let d = Date(timeIntervalSince1970: TimeInterval(h.changesPreset.since()))
            return "Since last \(d.formatted(.dateTime.weekday(.wide)))"
        case .month:
            return "Since \(dateText(h.changesPreset.since()))"
        }
    }

    @ViewBuilder
    private func content(_ c: Changes) -> some View {
        let keep = { (f: StoredFinding) in model.showInfo || f.severity > .info }
        let new = c.newFindings.filter(keep)
        let gone = c.resolvedFindings.filter(keep)
        let groups = (ChangeGroup.all + [ChangeGroup.of(StoredFinding.placeholder)]).compactMap { g -> (ChangeGroup, [StoredFinding], [StoredFinding], [ProgramRecord])? in
            let n = new.filter { ChangeGroup.of($0).id == g.id }
            let r = gone.filter { ChangeGroup.of($0).id == g.id }
            let p = g.id == "programs" ? c.newPrograms : []
            return n.isEmpty && r.isEmpty && p.isEmpty ? nil : (g, n, r, p)
        }
        Text(ChangeGroup.summary(c, since: sinceText, showInfo: model.showInfo))
            .font(.system(size: 15, weight: .semibold, design: .rounded))
            .foregroundStyle(Theme.ink)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.leading, 4)
        if groups.isEmpty {
            CalmEmptyState(symbol: "leaf", title: "Nothing changed",
                           message: "No new startup items, permissions or programs. Vogter kept watch the whole time.")
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(groups, id: \.0.id) { g, n, r, p in
                        VStack(alignment: .leading, spacing: 8) {
                            Label(g.title, systemImage: g.symbol)
                                .font(.system(size: 11.5, weight: .semibold, design: .rounded))
                                .foregroundStyle(Theme.inkFaint)
                                .padding(.leading, 4)
                            VStack(alignment: .leading, spacing: 0) {
                                let rows = n.map { ChangeRow(sign: "New", when: $0.firstSeen, title: $0.title, severity: $0.severity, path: $0.path) }
                                    + p.map { ChangeRow(sign: "First run", when: $0.firstSeen, title: "\($0.label) · \($0.runs) run\($0.runs == 1 ? "" : "s")", severity: nil, path: $0.identity.hasPrefix("path:") ? String($0.identity.dropFirst(5)) : nil) }
                                    + r.map { ChangeRow(sign: "Gone", when: $0.resolvedAt ?? $0.lastSeen, title: $0.title, severity: $0.severity, path: $0.path) }
                                ForEach(Array(rows.enumerated()), id: \.offset) { i, row in
                                    if i > 0 { Divider().overlay(Theme.hairline) }
                                    row
                                }
                            }
                            .zenCard(padding: 10)
                        }
                    }
                }
                .padding(8)
            }
            .padding(-8)
        }
    }
}

private struct ChangeRow: View {
    @Environment(AppModel.self) private var model
    let sign: String
    let when: UInt64
    let title: String
    let severity: Severity?
    let path: String?

    var body: some View {
        HStack(spacing: 10) {
            Text(sign)
                .font(.system(size: 10.5, weight: .semibold, design: .rounded))
                .foregroundStyle(sign == "Gone" ? Theme.inkFaint : Theme.moss)
                .padding(.horizontal, 7).padding(.vertical, 2)
                .background((sign == "Gone" ? Theme.inkFaint : Theme.sage).opacity(0.13), in: Capsule(style: .continuous))
                .frame(width: 70, alignment: .leading)
            Text(title).font(.system(size: 12.5, design: .rounded)).foregroundStyle(sign == "Gone" ? Theme.inkSoft : Theme.ink)
                .lineLimit(1)
            Spacer(minLength: 6)
            if let severity, severity > .info { SeverityBadge(severity: severity) }
            Text(dateText(when)).font(.system(size: 11, design: .rounded)).foregroundStyle(Theme.inkFaint).monospacedDigit()
            if let path {
                Button { model.history.openProfile(path) } label: {
                    Image(systemName: "person.text.rectangle").font(.system(size: 11.5)).foregroundStyle(Theme.inkSoft)
                }
                .buttonStyle(.plain)
                .help("Who is this?")
            }
        }
        .padding(.horizontal, 4)
        .padding(.vertical, 7)
    }
}

// MARK: Program profile

/// Opens the "Who is this?" sheet whenever `history.profilePath` is set.
struct ProgramProfileSheet: ViewModifier {
    @Environment(AppModel.self) private var model

    func body(content: Content) -> some View {
        @Bindable var h = model.history
        content.sheet(isPresented: Binding(get: { h.profilePath != nil }, set: { if !$0 { h.profilePath = nil } })) {
            ProgramProfileView()
                .environment(model)
                .frame(width: 560, height: 620)
                .zenBackground()
        }
    }
}

/// "Who is this?": everything Vogter knows about one program.
struct ProgramProfileView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        let h = model.history
        VStack(alignment: .leading, spacing: 0) {
            if let p = h.profile {
                ScrollView { content(p).padding(22) }
                Divider().overlay(Theme.hairline)
                HStack(spacing: 8) {
                    if p.exists {
                        Button("Show in Finder") { model.reveal(path: p.path) }.buttonStyle(SoftButtonStyle())
                    }
                    Spacer()
                    Button("Done") { close() }.buttonStyle(SoftButtonStyle()).keyboardShortcut(.cancelAction)
                    Button("Show in History") {
                        close()
                        model.showInHistory(program: p.path)
                    }
                    .buttonStyle(SoftButtonStyle(prominent: true))
                }
                .padding(.horizontal, 22)
                .padding(.vertical, 14)
            } else {
                VStack(spacing: 12) {
                    ProgressView().controlSize(.small)
                    Text("Gathering what Vogter knows…").font(.system(size: 12, design: .rounded)).foregroundStyle(Theme.inkSoft)
                    Button("Done") { close() }.buttonStyle(SoftButtonStyle()).keyboardShortcut(.cancelAction)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .fontDesign(.rounded)
        .tint(Theme.sage)
    }

    private func close() {
        model.history.profilePath = nil
        dismiss()
    }

    private func content(_ p: ProgramProfile) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Squircle(symbol: "person.text.rectangle", tint: Theme.mist, size: 42)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Who is \(p.name)?").font(.system(size: 17, weight: .semibold, design: .rounded)).foregroundStyle(Theme.ink)
                    Text(intro(p)).font(.system(size: 12, design: .rounded)).foregroundStyle(Theme.inkSoft)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            MonoBox(text: p.path)

            VStack(alignment: .leading, spacing: 0) {
                fact("First seen here", p.familiarity.map { Date(timeIntervalSince1970: TimeInterval($0.firstSeen)).formatted(date: .abbreviated, time: .shortened) } ?? "Never seen starting")
                if let f = p.familiarity {
                    fact("Last seen", Date(timeIntervalSince1970: TimeInterval(f.lastSeen)).formatted(date: .abbreviated, time: .shortened))
                    fact("Runs", "\(f.runs)")
                }
                fact("Signature", p.signing.map { $0.summary + ($0.identifier.map { " · \($0)" } ?? "") } ?? "Unknown")
                fact("On disk", p.exists ? "Yes" : "No longer there", last: true)
            }
            .zenCard(padding: 12)

            if !p.findings.isEmpty {
                group("Right now", symbol: "shield") {
                    ForEach(p.findings) { f in
                        HStack(alignment: .top, spacing: 8) {
                            Squircle(symbol: f.symbol, tint: f.severity.color, size: 22)
                            Text(f.title).font(.system(size: 12.5, design: .rounded)).foregroundStyle(Theme.ink)
                            Spacer()
                            SeverityBadge(severity: f.severity)
                        }
                        .padding(.vertical, 3)
                    }
                }
            }
            if !p.pastFindings.isEmpty {
                group("In the past", symbol: "clock") {
                    ForEach(p.pastFindings) { f in PastFindingRow(finding: f) }
                }
            }
            group(p.eventCount == 0 ? "Activity" : "Activity · \(p.eventCount) in history", symbol: "list.bullet") {
                if p.events.isEmpty {
                    Text("No alerts about it.").font(.system(size: 12, design: .rounded)).foregroundStyle(Theme.inkSoft)
                }
                ForEach(p.events.prefix(8)) { e in
                    HStack(alignment: .top, spacing: 8) {
                        Squircle(symbol: e.symbol, tint: e.severity.map(\.color) ?? Theme.inkFaint, size: 22)
                        Text(e.text).font(.system(size: 12.5, design: .rounded)).foregroundStyle(Theme.ink).lineLimit(2)
                        Spacer(minLength: 6)
                        if e.note != nil { Image(systemName: "note.text").font(.system(size: 11)).foregroundStyle(Theme.moss) }
                        Text(dateText(e.at)).font(.system(size: 11, design: .rounded)).foregroundStyle(Theme.inkFaint)
                    }
                    .padding(.vertical, 3)
                }
            }
        }
    }

    private func intro(_ p: ProgramProfile) -> String {
        guard let f = p.familiarity else { return "Vogter hasn't seen it start, but it appears in your history." }
        let days = (UInt64(Date().timeIntervalSince1970) - min(f.firstSeen, UInt64(Date().timeIntervalSince1970))) / 86_400
        let since = days == 0 ? "today" : days == 1 ? "yesterday" : "\(days) days ago"
        return "First ran here \(since) · \(f.runs) run\(f.runs == 1 ? "" : "s") so far."
    }

    private func fact(_ label: String, _ value: String, last: Bool = false) -> some View {
        VStack(spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text(label).foregroundStyle(Theme.ink)
                Spacer(minLength: 16)
                Text(value).foregroundStyle(Theme.inkSoft).multilineTextAlignment(.trailing).textSelection(.enabled)
            }
            .font(.system(size: 12.5, design: .rounded))
            .padding(.vertical, 6)
            if !last { Divider().overlay(Theme.hairline) }
        }
    }

    private func group<Content: View>(_ title: String, symbol: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: symbol)
                .font(.system(size: 11.5, weight: .semibold, design: .rounded))
                .foregroundStyle(Theme.inkFaint)
                .padding(.leading, 4)
            VStack(alignment: .leading, spacing: 4) { content() }
                .frame(maxWidth: .infinity, alignment: .leading)
                .zenCard(padding: 12)
        }
    }
}
