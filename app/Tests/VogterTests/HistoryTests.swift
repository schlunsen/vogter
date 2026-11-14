import XCTest
@testable import Vogter

/// History replies, captured from a test vogterd (sanitized: generic names, /Users/me).
final class HistoryTests: XCTestCase {
    private func decode(_ json: String) throws -> DaemonMessage {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return try d.decode(DaemonMessage.self, from: Data(json.utf8))
    }

    private func fixture(_ name: String) throws -> DaemonMessage {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
        return try decode(String(contentsOf: url, encoding: .utf8))
    }

    func testHistoryPage() throws {
        guard case let .history(events, next, token) = try fixture("history") else { return XCTFail("not history") }
        XCTAssertEqual(token, 7)
        XCTAssertEqual(next, events.last?.id)
        XCTAssertEqual(events.map(\.id), events.map(\.id).sorted(by: >), "newest first")
        let noted = try XCTUnwrap(events.first { $0.note != nil })
        XCTAssertNotNil(noted.reviewedAt)
        XCTAssertEqual(noted.programPath, "/Users/me/Library/Application Support/PrintStudio/PrintStudio Helper")
        XCTAssertTrue(events.contains { if case .newFinding = $0.kind { true } else { false } })
        XCTAssertTrue(events.allSatisfy { $0.note == nil || $0.id == noted.id })
    }

    func testDaySummaries() throws {
        guard case let .historyDays(days) = try fixture("history_days") else { return XCTFail("not days") }
        XCTAssertFalse(days.isEmpty)
        for d in days {
            XCTAssertEqual(d.counts.count, 5)
            XCTAssertEqual(d.counts.reduce(0, +), d.events)
            XCTAssertEqual(d.day.count, 10)
        }
    }

    func testFindingHistory() throws {
        guard case let .findingHistory(findings, token) = try fixture("finding_history") else { return XCTFail() }
        XCTAssertEqual(token, 8)
        let gone = try XCTUnwrap(findings.first { $0.resolvedAt != nil })
        XCTAssertGreaterThanOrEqual(gone.resolvedAt!, gone.lastSeen)
        XCTAssertTrue(findings.contains { $0.resolvedAt == nil })
    }

    func testAwayPeriods() throws {
        guard case let .awayPeriods(periods) = try fixture("away_periods") else { return XCTFail() }
        XCTAssertTrue(periods.contains { $0.until != nil })
        XCTAssertTrue(periods.allSatisfy { $0.until.map { $0 > $0 - 1 } ?? true })
    }

    func testProgramProfile() throws {
        guard case let .programProfile(p) = try fixture("program_profile") else { return XCTFail() }
        XCTAssertEqual(p.name, "PrintStudio Helper")
        XCTAssertEqual(p.familiarity?.runs, 2)
        XCTAssertEqual(p.signing?.kind, "ad_hoc")
        XCTAssertEqual(p.eventCount, UInt32(p.events.count))
        XCTAssertFalse(p.pastFindings.isEmpty)
    }

    func testChanges() throws {
        guard case let .changes(c) = try fixture("changes") else { return XCTFail() }
        XCTAssertFalse(c.newFindings.isEmpty)
        XCTAssertFalse(c.resolvedFindings.isEmpty)
        XCTAssertEqual(c.newPrograms.first?.label, "PrintStudio Helper")
        let line = ChangeGroup.summary(c, since: "Since last week", showInfo: false)
        XCTAssertEqual(line, "Since last week: 1 new startup item, 1 new program, 1 new protection change, 1 went away")
    }

    func testAnnotation() throws {
        guard case let .annotation(id, note, reviewedAt) = try fixture("annotation") else { return XCTFail() }
        XCTAssertEqual(id, 4)
        XCTAssertEqual(note, "That was me — I mistyped my password.")
        XCTAssertNil(reviewedAt)
    }

    // MARK: Timeline grouping

    private func event(_ id: Int64, at: UInt64, kind: String = "sudo") throws -> LoggedEvent {
        let json = #"{"id":\#(id),"at":\#(at),"kind":"activity","activity":{"kind":"\#(kind)","severity":"low","summary":"s"}}"#
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return try d.decode(LoggedEvent.self, from: Data(json.utf8))
    }

    @MainActor
    func testSectionsGroupByHourAndFoldAwayTime() throws {
        let day = HistoryModel.startOfDay(Date(timeIntervalSince1970: 1_793_750_400))
        let h = { (hour: UInt64, min: UInt64) in day + hour * 3600 + min * 60 }
        let events = try [
            event(7, at: h(17, 10)),
            event(6, at: h(16, 0), kind: "screen_unlocked"),
            event(5, at: h(15, 20)),
            event(4, at: h(14, 0), kind: "screen_locked"),
            event(3, at: h(13, 50)),
            event(2, at: h(13, 5)),
            event(1, at: h(9, 0)),
        ]
        let away = [AwayPeriod(from: h(14, 0), until: h(16, 0)), AwayPeriod(from: h(11, 0), until: h(12, 0))]
        let s = HistoryModel.sections(events: events, away: away, showEmptyAway: true, range: (day, day + 86_400))
        XCTAssertEqual(s.map(\.events.count), [1, 1, 2, 0, 1])
        XCTAssertEqual(s[1].kind, .away(away[0]), "lock and unlock fold into the band")
        XCTAssertEqual(s[3].kind, .away(away[1]), "an empty band sits at its time")
        XCTAssertEqual(s.compactMap(\.day), [day])
        // Filtered views leave out empty bands.
        XCTAssertEqual(HistoryModel.sections(events: events, away: away, showEmptyAway: false).count, 4)
    }

    @MainActor
    func testRecentDaysFillQuietDays() {
        let h = HistoryModel()
        let today = HistoryModel.startOfDay(Date())
        h.days = [DaySummary(day: HistoryModel.dayString(today), start: today, events: 5, counts: [2, 1, 1, 1, 0])]
        let rows = h.recentDays()
        XCTAssertEqual(rows.count, HistoryModel.recentDayCount)
        XCTAssertEqual(rows[0].title, "Today")
        XCTAssertEqual(rows[0].mood, "2 to look at")
        XCTAssertEqual(rows[1].title, "Yesterday")
        XCTAssertEqual(rows[1].mood, "quiet")
        XCTAssertEqual(h.heatmap().count, HistoryModel.heatmapWeeks)
        XCTAssertTrue(h.heatmap().allSatisfy { $0.count == 7 })
    }

    @MainActor
    func testPushedEventsCountForToday() throws {
        let h = HistoryModel()
        h.didReceive(try event(9, at: UInt64(Date().timeIntervalSince1970)))
        XCTAssertEqual(h.days.first?.counts, [0, 1, 0, 0, 0])
        XCTAssertEqual(h.events.map(\.id), [9])
    }

    @MainActor
    func testExport() throws {
        var e = try event(3, at: 1_793_750_400)
        e.note = "said \"hi\", twice\nreally"
        let csv = String(decoding: HistoryModel.exportData(events: [e], format: .csv), as: UTF8.self)
        let lines = csv.components(separatedBy: "\r\n")
        XCTAssertEqual(lines[0], "id,time,severity,kind,summary,detail,process,path,note,reviewed")
        XCTAssertTrue(lines[1].hasPrefix("3,"))
        XCTAssertTrue(csv.contains("\"said \"\"hi\"\", twice\nreally\""))
        let json = try JSONSerialization.jsonObject(with: HistoryModel.exportData(events: [e], format: .json)) as? [[String: Any]]
        XCTAssertEqual(json?.first?["kind"] as? String, "sudo")
        XCTAssertEqual(json?.first?["severity"] as? String, "low")
    }

    @MainActor
    func testDemoHistory() {
        let h = Demo.model().history
        XCTAssertFalse(h.events.isEmpty)
        XCTAssertEqual(h.away.count, 1)
        XCTAssertNotNil(h.changes)
        XCTAssertNotNil(h.profile)
        XCTAssertNil(h.profilePath, "the sheet must not open in screenshots")
        XCTAssertGreaterThan(h.days.count, 150)
    }
}
