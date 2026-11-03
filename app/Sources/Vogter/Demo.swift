import Foundation

/// Made-up data for the README screenshots (`Vogter --render-screenshots <dir>`).
/// Nothing here comes from the Mac it runs on. The texts follow what vogterd really
/// produces (see crates/vogter-detect and crates/vogterd), and everything is decoded
/// through the same Codable mirrors the app uses for daemon messages.
enum Demo {
    /// Event id of the alert shown in the Activity tab's detail pane.
    static let selectedEventID: Int64 = 112
    /// The pid of the fake password dialog, shown as "still running".
    static let runningPID: Int32 = 4821

    @MainActor
    static func model() -> AppModel {
        let model = AppModel(connect: false)
        let now = UInt64(Date().timeIntervalSince1970)
        model.connected = true
        model.socketPath = "/var/run/vogter.sock"
        model.status = decode(DaemonStatus.self, status(now: now))
        model.findings = decode([StoredFinding].self, findings(now: now))
        model.events = decode([LoggedEvent].self, events(now: now))
        model.trustRules = decode([TrustRule].self, trustRules(now: now))
        model.selectedEventID = selectedEventID
        model.simulatedRunningPIDs = [runningPID]
        return model
    }

    private static func decode<T: Decodable>(_ type: T.Type, _ json: String) -> T {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        do {
            return try d.decode(T.self, from: Data(json.utf8))
        } catch {
            fatalError("demo data does not decode as \(T.self): \(error)")
        }
    }

    private static func status(now: UInt64) -> String {
        """
        {"type":"status","protocol":1,"version":"0.1.0","as_root":true,"scanning":false,
         "last_scan":\(now - 140),"scan_interval_secs":300,"open_counts":[0,1,2,0,0],
         "av":{"microphone_in_use":true,"microphone_clients":[{"pid":3310,"name":"zoom.us","bundle_id":"us.zoom.xos"}],
               "camera_in_use":false},
         "sensor_errors":[],
         "realtime":{"endpoint_security":false,
                     "endpoint_security_error":"Endpoint Security unavailable: NotEntitled (the binary is not signed with the Endpoint Security entitlement)",
                     "sources":["fs_events","process_poll","session_notify","sudo_log"]},
         "learning_until":\(now - 20 * 86_400),"trust_rules":2}
        """
    }

    private static func findings(now: UInt64) -> String {
        """
        [
         {"key":"keylogger.event_tap|/Applications/QuickBar.app/Contents/MacOS/QuickBar|QuickBar can read your keystrokes",
          "severity":"medium","category":"keylogger","check":"keylogger.event_tap",
          "title":"QuickBar can read your keystrokes",
          "detail":"Keyboard event tap #14 on all apps, listen-only (observes silently, the usual keylogger shape). Signed: developer 7XK2Q9M4LP, notarized [com.example.quickbar]. Fine if you installed it as a keyboard tool (launcher, remapper, text expander).",
          "pid":912,"path":"/Applications/QuickBar.app/Contents/MacOS/QuickBar",
          "signing":{"kind":"third_party","identifier":"com.example.quickbar","team_id":"7XK2Q9M4LP","notarized":true},
          "first_seen":\(now - 3 * 3600),"last_seen":\(now - 140),"acknowledged":false},
         {"key":"persistence.script|/bin/bash|Launch item com.example.helper",
          "severity":"medium","category":"persistence","check":"persistence.script",
          "title":"Launch item com.example.helper",
          "detail":"/Users/me/Library/LaunchAgents/com.example.helper.plist starts when you log in: runs a script: `/bin/bash /Users/me/Library/Application Support/PrintStudio/update.sh`",
          "path":"/bin/bash",
          "signing":{"kind":"apple","identifier":"com.apple.bash","notarized":false},
          "first_seen":\(now - 26 * 3600),"last_seen":\(now - 140),"acknowledged":false},
         {"key":"health.firewall||The macOS firewall is off",
          "severity":"low","category":"system_health","check":"health.firewall",
          "title":"The macOS firewall is off",
          "detail":"Incoming connections to apps are not filtered.",
          "first_seen":\(now - 9 * 86_400),"last_seen":\(now - 140),"acknowledged":false}
        ]
        """
    }

    private static func events(now: UInt64) -> String {
        let passwordAdvice = "Real macOS password prompts come from the system, not from scripts. If you didn't just run a script that needs your password, don't type it in. Note which program started it (below), quit it, and check startup items and recent downloads."
        let sudoAdvice = "Someone tried to run a command as administrator and failed. Fine if that was you mistyping your password; repeated failures you didn't cause are worth looking into."
        return """
        [
         {"id":112,"at":\(now - 4 * 60),"kind":"activity","activity":{"kind":"process_started","severity":"critical",
          "summary":"osascript: Shows a password dialog from a script (a common way to steal your password)",
          "advice":"\(passwordAdvice)",
          "detail":"`osascript -e display dialog \\"macOS needs your password to install an update.\\" default answer \\"\\" with hidden answer` — started by /Users/me/Downloads/PrintStudio Installer.app/Contents/MacOS/installer",
          "pid":\(runningPID),"process":"osascript","path":"/usr/bin/osascript",
          "signing":{"kind":"apple","identifier":"com.apple.osascript","notarized":false}}},
         {"id":111,"at":\(now - 11 * 60),"kind":"microphone_on","clients":[{"pid":3310,"name":"zoom.us","bundle_id":"us.zoom.xos"}]},
         {"id":110,"at":\(now - 38 * 60),"kind":"activity","activity":{"kind":"away_summary","severity":"medium",
          "summary":"While you were away (2h 10m): 1 alert, 3 programs started",
          "detail":"[medium] Failed sudo by me: 3 incorrect password attempts\\nPrograms: PrintStudio Helper, mdworker_shared, softwareupdated"}},
         {"id":109,"at":\(now - 38 * 60),"kind":"activity","activity":{"kind":"screen_unlocked","severity":"info","summary":"Screen unlocked"}},
         {"id":108,"at":\(now - 95 * 60),"kind":"activity","activity":{"kind":"sudo","severity":"medium",
          "summary":"Failed sudo by me: 3 incorrect password attempts",
          "advice":"\(sudoAdvice)",
          "detail":"/bin/cat /etc/sudoers"}},
         {"id":107,"at":\(now - 168 * 60),"kind":"activity","activity":{"kind":"screen_locked","severity":"info","summary":"Screen locked"}},
         {"id":106,"at":\(now - 175 * 60),"kind":"scan_completed","findings":3,"new":1,"resolved":0,"baseline":false},
         {"id":105,"at":\(now - 176 * 60),"kind":"new_finding","finding":
          {"key":"keylogger.event_tap|/Applications/QuickBar.app/Contents/MacOS/QuickBar|QuickBar can read your keystrokes",
           "severity":"medium","category":"keylogger","check":"keylogger.event_tap",
           "title":"QuickBar can read your keystrokes",
           "detail":"Keyboard event tap #14 on all apps, listen-only (observes silently, the usual keylogger shape).",
           "pid":912,"path":"/Applications/QuickBar.app/Contents/MacOS/QuickBar",
           "signing":{"kind":"third_party","identifier":"com.example.quickbar","team_id":"7XK2Q9M4LP","notarized":true},
           "first_seen":\(now - 176 * 60),"last_seen":\(now - 176 * 60),"acknowledged":false}},
         {"id":104,"at":\(now - 180 * 60),"kind":"activity","activity":{"kind":"process_started","severity":"low",
          "summary":"First run of PrintStudio Helper",
          "detail":"/Users/me/Library/Application Support/PrintStudio/PrintStudio Helper — ad-hoc signed (no identity)",
          "pid":4410,"process":"PrintStudio Helper","path":"/Users/me/Library/Application Support/PrintStudio/PrintStudio Helper",
          "signing":{"kind":"ad_hoc","notarized":false}}},
         {"id":103,"at":\(now - 182 * 60),"kind":"activity","activity":{"kind":"persistence_changed","severity":"low",
          "summary":"Startup item added: com.example.helper.plist",
          "path":"/Users/me/Library/LaunchAgents/com.example.helper.plist"}},
         {"id":102,"at":\(now - 5 * 3600),"kind":"microphone_off"},
         {"id":101,"at":\(now - 6 * 3600),"kind":"resolved","key":"health.remote_login||Remote Login (SSH) is on","title":"Remote Login (SSH) is on"}
        ]
        """
    }

    private static func trustRules(now: UInt64) -> String {
        """
        [
         {"id":3,"check":"keylogger","subject":{"type":"developer","team_id":"4HB8N2RJ6C","identifier":"com.example.textexpander"},
          "label":"TypeFast (developer 4HB8N2RJ6C)","created_at":\(now - 4 * 86_400)},
         {"id":2,"check":"*","subject":{"type":"file","path":"/Users/me/bin/backup.sh","sha256":"9f2c41d7a0b3e5f6"},
          "label":"/Users/me/bin/backup.sh (contents 9f2c41d7a0b3)","created_at":\(now - 12 * 86_400)}
        ]
        """
    }
}
