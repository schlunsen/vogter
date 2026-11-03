import XCTest
@testable import Vogter

/// Fixtures are real lines captured from vogterd, so these catch drift between
/// the Rust protocol and the Swift mirrors.
final class DecodingTests: XCTestCase {
    private func decode(_ json: String) throws -> DaemonMessage {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return try d.decode(DaemonMessage.self, from: Data(json.utf8))
    }

    private func fixture(_ name: String) throws -> String {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
        return try String(contentsOf: url, encoding: .utf8)
    }

    func testStatus() throws {
        guard case let .status(s) = try decode(fixture("status")) else { return XCTFail("not status") }
        XCTAssertEqual(s.protocol, 1)
        XCTAssertEqual(s.openCounts.count, 5)
        XCTAssertNotNil(s.lastScan)
    }

    func testFindings() throws {
        guard case let .findings(f) = try decode(fixture("findings")) else { return XCTFail("not findings") }
        XCTAssertFalse(f.isEmpty)
        XCTAssertTrue(f.allSatisfy { !$0.key.isEmpty && $0.firstSeen > 0 })
    }

    func testEvents() throws {
        guard case let .events(e) = try decode(fixture("events")) else { return XCTFail("not events") }
        XCTAssertTrue(e.contains { if case .scanCompleted(_, _, _, true) = $0.kind { true } else { false } })
    }

    func testPushedEventWithClients() throws {
        let json = #"{"type":"event","id":9,"at":1,"kind":"microphone_on","clients":[{"pid":42,"name":"zoom.us","bundle_id":"us.zoom.xos"}]}"#
        guard case let .event(e) = try decode(json), case let .microphoneOn(clients) = e.kind else {
            return XCTFail("not a microphone event")
        }
        XCTAssertEqual(clients, [AudioClient(pid: 42, name: "zoom.us", bundleId: "us.zoom.xos")])
        XCTAssertEqual(e.text, "Microphone on — zoom.us")
    }

    func testNewFindingEvent() throws {
        let json = #"{"type":"event","id":1,"at":1,"kind":"new_finding","finding":{"key":"k","severity":"high","category":"keylogger","check":"keylogger.event_tap","title":"x can read your keystrokes","detail":"d","pid":5,"signing":{"kind":"ad_hoc","notarized":false},"first_seen":1,"last_seen":1,"acknowledged":false}}"#
        guard case let .event(e) = try decode(json), case let .newFinding(f) = e.kind else { return XCTFail() }
        XCTAssertEqual(f.severity, .high)
        XCTAssertEqual(f.signing?.summary, "ad-hoc signed (no identity)")
    }

    func testRealtimeStatus() throws {
        guard case let .status(s) = try decode(fixture("status")) else { return XCTFail("not status") }
        let rt = try XCTUnwrap(s.realtime)
        XCTAssertFalse(rt.endpointSecurity)
        XCTAssertTrue(rt.sources.contains("process_poll"))
    }

    func testActivityEventsFromDaemon() throws {
        guard case let .events(e) = try decode(fixture("events")) else { return XCTFail("not events") }
        let activities = e.compactMap { if case let .activity(a) = $0.kind { a } else { nil } }
        XCTAssertFalse(activities.isEmpty)
        XCTAssertTrue(activities.contains { $0.kind == "sudo" })
        XCTAssertTrue(activities.contains { $0.kind == "process_started" && $0.severity >= .high })
    }

    func testActivityAdvice() throws {
        let json = #"{"type":"event","id":4,"at":1,"kind":"activity","activity":{"kind":"process_started","severity":"high","summary":"zsh: Decodes hidden (base64) code and runs it","advice":"Hidden (encoded) code is being run.","detail":"`zsh -c …`","pid":42,"process":"zsh","path":"/bin/zsh","signing":{"kind":"apple","identifier":"com.apple.zsh","notarized":false}}}"#
        guard case let .event(e) = try decode(json), case let .activity(a) = e.kind else { return XCTFail() }
        XCTAssertEqual(a.advice, "Hidden (encoded) code is being run.")
        XCTAssertEqual(a.pid, 42)
    }

    func testAwaySummary() throws {
        let json = #"{"type":"event","id":3,"at":1,"kind":"activity","activity":{"kind":"away_summary","severity":"medium","summary":"While you were away (2h 0m): 1 alert, 0 programs started","detail":"[medium] Failed sudo by x"}}"#
        guard case let .event(e) = try decode(json), case let .activity(a) = e.kind else { return XCTFail() }
        XCTAssertEqual(a.kind, "away_summary")
        XCTAssertEqual(e.symbol, "figure.walk.departure")
        XCTAssertEqual(e.severity, .medium)
    }

    func testTrustRules() throws {
        let json = #"{"type":"trust_rules","rules":[{"id":1,"check":"process","subject":{"type":"file","path":"/tmp/x","sha256":"7d13d4f7db9b"},"label":"/tmp/x (contents 7d13d4f7db9b)","created_at":5},{"id":2,"check":"*","subject":{"type":"developer","team_id":"ABCDE12345","identifier":"com.example.app"},"label":"App (developer ABCDE12345)","created_at":6}]}"#
        guard case let .trustRules(rules) = try decode(json) else { return XCTFail("not trust rules") }
        XCTAssertEqual(rules.count, 2)
        XCTAssertEqual(rules[0].subject.kindLabel, "File (exact contents)")
        XCTAssertEqual(rules[1].subject, .developer(teamId: "ABCDE12345", identifier: "com.example.app"))
    }

    func testUnknownTypesDoNotThrow() throws {
        guard case .unknown("future") = try decode(#"{"type":"future"}"#) else { return XCTFail() }
    }

    /// The screenshot demo data goes through the same decoders, and the offline model
    /// never connects.
    @MainActor
    func testDemoModel() {
        let model = Demo.model()
        XCTAssertEqual(model.findings.count, 3)
        XCTAssertEqual(model.trustRules.count, Int(model.status?.trustRules ?? 0))
        XCTAssertEqual(model.selectedEvent?.severity, .critical)
        XCTAssertNotNil(model.selectedEvent.flatMap { if case let .activity(a) = $0.kind { a.advice } else { nil } })
        XCTAssertEqual(model.recentAlerts.count, 3)
        XCTAssertTrue(model.isRunning(pid: Demo.runningPID, path: nil))
    }
}
