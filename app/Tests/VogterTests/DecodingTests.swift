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

    func testUnknownTypesDoNotThrow() throws {
        guard case .unknown("future") = try decode(#"{"type":"future"}"#) else { return XCTFail() }
    }
}
