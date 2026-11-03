import Foundation

// Mirrors of the Rust types in crates/vogter-model and crates/vogter-ipc.
// JSON keys are snake_case; we decode with .convertFromSnakeCase.

enum Severity: String, Codable, CaseIterable, Comparable {
    case info, low, medium, high, critical

    var rank: Int { Severity.allCases.firstIndex(of: self)! }
    static func < (a: Severity, b: Severity) -> Bool { a.rank < b.rank }

    var label: String { rawValue.capitalized }
}

struct Signing: Codable, Hashable {
    var kind: String
    var identifier: String?
    var teamId: String?
    var notarized: Bool

    var summary: String {
        switch kind {
        case "apple": return "Apple"
        case "third_party":
            let team = teamId.map { "developer \($0)" } ?? "developer"
            return notarized ? "\(team), notarized" : "\(team), not notarized"
        case "ad_hoc": return "ad-hoc signed (no identity)"
        case "untrusted": return "non-Apple certificate"
        case "unsigned": return "unsigned"
        case "invalid": return "invalid signature"
        default: return "unknown signature"
        }
    }
}

struct StoredFinding: Codable, Identifiable, Hashable {
    var key: String
    var severity: Severity
    var category: String
    var check: String
    var title: String
    var detail: String
    var pid: Int32?
    var path: String?
    var signing: Signing?
    var firstSeen: UInt64
    var lastSeen: UInt64
    var acknowledged: Bool

    var id: String { key }
}

struct AudioClient: Codable, Hashable {
    var pid: Int32
    var name: String
    var bundleId: String?
}

struct AvState: Codable, Hashable {
    var microphoneInUse: Bool
    var microphoneClients: [AudioClient]
    var cameraInUse: Bool
}

struct Activity: Codable, Hashable {
    var kind: String
    var severity: Severity
    var summary: String
    var detail: String?
    var pid: Int32?
    var process: String?
    var path: String?
    var signing: Signing?
}

struct Realtime: Codable, Hashable {
    var endpointSecurity: Bool
    var endpointSecurityError: String?
    var sources: [String]
}

enum TrustSubject: Decodable, Hashable {
    case developer(teamId: String, identifier: String?)
    case file(path: String, sha256: String?)
    case exact(key: String)
    case unknown

    private enum Keys: String, CodingKey { case type, teamId, identifier, path, sha256, key }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        switch try c.decode(String.self, forKey: .type) {
        case "developer":
            self = .developer(teamId: try c.decode(String.self, forKey: .teamId),
                              identifier: try c.decodeIfPresent(String.self, forKey: .identifier))
        case "file":
            self = .file(path: try c.decode(String.self, forKey: .path), sha256: try c.decodeIfPresent(String.self, forKey: .sha256))
        case "exact": self = .exact(key: try c.decode(String.self, forKey: .key))
        default: self = .unknown
        }
    }

    var kindLabel: String {
        switch self {
        case .developer: return "Developer"
        case let .file(_, hash): return hash == nil ? "Path" : "File (exact contents)"
        case .exact: return "This alert only"
        case .unknown: return "Other"
        }
    }
}

struct TrustRule: Decodable, Identifiable, Hashable {
    var id: Int64
    var check: String
    var subject: TrustSubject
    var label: String
    var createdAt: UInt64
}

struct DaemonStatus: Codable {
    var `protocol`: Int
    var version: String
    var asRoot: Bool
    var scanning: Bool
    var lastScan: UInt64?
    var scanIntervalSecs: UInt64
    /// Indexed by Severity.rank.
    var openCounts: [UInt32]
    var av: AvState
    var sensorErrors: [String]
    var realtime: Realtime?
    var learningUntil: UInt64?
    var trustRules: UInt32?
}

enum EventKind: Hashable {
    case scanCompleted(findings: Int, new: Int, resolved: Int, baseline: Bool)
    case newFinding(StoredFinding)
    case resolved(key: String, title: String)
    case activity(Activity)
    case microphoneOn([AudioClient])
    case microphoneOff
    case cameraOn
    case cameraOff
    case unknown(String)
}

struct LoggedEvent: Decodable, Identifiable, Hashable {
    var id: Int64
    var at: UInt64
    var kind: EventKind

    private enum Keys: String, CodingKey {
        case id, at, kind, findings, new, resolved, baseline, finding, key, title, clients, activity
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        id = try c.decode(Int64.self, forKey: .id)
        at = try c.decode(UInt64.self, forKey: .at)
        switch try c.decode(String.self, forKey: .kind) {
        case "scan_completed":
            kind = .scanCompleted(
                findings: try c.decode(Int.self, forKey: .findings),
                new: try c.decode(Int.self, forKey: .new),
                resolved: try c.decode(Int.self, forKey: .resolved),
                baseline: try c.decode(Bool.self, forKey: .baseline))
        case "new_finding": kind = .newFinding(try c.decode(StoredFinding.self, forKey: .finding))
        case "resolved":
            kind = .resolved(key: try c.decode(String.self, forKey: .key), title: try c.decode(String.self, forKey: .title))
        case "activity": kind = .activity(try c.decode(Activity.self, forKey: .activity))
        case "microphone_on": kind = .microphoneOn(try c.decode([AudioClient].self, forKey: .clients))
        case "microphone_off": kind = .microphoneOff
        case "camera_on": kind = .cameraOn
        case "camera_off": kind = .cameraOff
        case let other: kind = .unknown(other)
        }
    }

    var text: String {
        switch kind {
        case let .scanCompleted(findings, new, resolved, baseline):
            return baseline ? "First scan: \(findings) findings recorded as baseline"
                : "Scan: \(new) new, \(resolved) gone (\(findings) total)"
        case let .newFinding(f): return "New: \(f.title)"
        case let .resolved(_, title): return "Gone: \(title)"
        case let .activity(a): return a.summary
        case let .microphoneOn(clients):
            let who = clients.map(\.name).joined(separator: ", ")
            return "Microphone on" + (who.isEmpty ? "" : " — \(who)")
        case .microphoneOff: return "Microphone off"
        case .cameraOn: return "Camera on"
        case .cameraOff: return "Camera off"
        case let .unknown(k): return k
        }
    }

    /// Severity for display; nil for plain status events.
    var severity: Severity? {
        switch kind {
        case let .activity(a): return a.severity
        case let .newFinding(f): return f.severity
        default: return nil
        }
    }

    var detail: String? {
        if case let .activity(a) = kind { return a.detail }
        return nil
    }

    var symbol: String {
        switch kind {
        case .scanCompleted: return "magnifyingglass"
        case .newFinding: return "exclamationmark.triangle"
        case .resolved: return "checkmark.circle"
        case let .activity(a):
            switch a.kind {
            case "process_started": return "terminal"
            case "sensitive_file_read": return "key.fill"
            case "persistence_changed": return "arrow.clockwise.circle"
            case "permission_changed": return "hand.raised"
            case "sudo": return "lock.open"
            case "remote_login", "screen_sharing": return "network"
            case "screen_locked": return "lock"
            case "screen_unlocked": return "lock.open.display"
            case "malware_detected": return "ladybug.fill"
            case "away_summary": return "figure.walk.departure"
            default: return "bolt"
            }
        case .microphoneOn: return "mic.fill"
        case .microphoneOff: return "mic.slash"
        case .cameraOn: return "video.fill"
        case .cameraOff: return "video.slash"
        case .unknown: return "questionmark"
        }
    }
}

/// One line from the daemon.
enum DaemonMessage: Decodable {
    case status(DaemonStatus)
    case findings([StoredFinding])
    case events([LoggedEvent])
    case trusted(TrustRule)
    case trustRules([TrustRule])
    case ok
    case error(String)
    case event(LoggedEvent)
    case unknown(String)

    private enum Keys: String, CodingKey { case type, findings, events, message, rule, rules }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        switch try c.decode(String.self, forKey: .type) {
        case "status": self = .status(try DaemonStatus(from: decoder))
        case "findings": self = .findings(try c.decode([StoredFinding].self, forKey: .findings))
        case "events": self = .events(try c.decode([LoggedEvent].self, forKey: .events))
        case "trusted": self = .trusted(try c.decode(TrustRule.self, forKey: .rule))
        case "trust_rules": self = .trustRules(try c.decode([TrustRule].self, forKey: .rules))
        case "ok": self = .ok
        case "error": self = .error(try c.decode(String.self, forKey: .message))
        case "event": self = .event(try LoggedEvent(from: decoder))
        case let other: self = .unknown(other)
        }
    }
}

func relativeTime(_ unix: UInt64) -> String {
    let date = Date(timeIntervalSince1970: TimeInterval(unix))
    let f = RelativeDateTimeFormatter()
    f.unitsStyle = .short
    return f.localizedString(for: date, relativeTo: Date())
}
