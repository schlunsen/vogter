import Foundation

/// Made-up history for the History tab's screenshots. Like `Demo`, nothing here comes
/// from this Mac, and everything goes through the app's real decoders.
extension Demo {
    static let helperPath = "/Users/me/Library/Application Support/PrintStudio/PrintStudio Helper"

    /// The shown day's events happen in a fixed afternoon, so the timeline looks the same
    /// whenever the screenshots are rendered.
    static func historyAnchor(now: Date = Date()) -> UInt64 {
        UInt64(Calendar.current.startOfDay(for: now).timeIntervalSince1970) + 16 * 3600 + 40 * 60
    }

    @MainActor
    static func fillHistory(_ h: HistoryModel) {
        let anchor = historyAnchor()
        let today = HistoryModel.startOfDay(Date())
        var events = decode([LoggedEvent].self, self.events(now: anchor)) + decode([LoggedEvent].self, morning(today: today))
        if let i = events.firstIndex(where: { $0.id == 104 }) {
            events[i].note = "That's the PrintStudio installer I ran. Fine."
            events[i].reviewedAt = anchor - 170 * 60
        }
        if let i = events.firstIndex(where: { $0.id == 108 }) { events[i].reviewedAt = anchor - 30 * 60 }
        h.events = events.sorted { $0.id > $1.id }
        h.away = [AwayPeriod(from: anchor - 168 * 60, until: anchor - 38 * 60)]
        h.selectedDay = today
        h.days = days(today: today, events: h.events)
        h.pastFindings = decode([StoredFinding].self, pastFindings(now: anchor))
        h.changes = decode(Changes.self, changes(now: anchor))
        h.profile = decode(ProgramProfile.self, profile(now: anchor))
    }

    private static func morning(today: UInt64) -> String {
        let t = { (h: UInt64, m: UInt64) in today + h * 3600 + m * 60 }
        return """
        [
         {"id":100,"at":\(t(9, 58)),"kind":"camera_off"},
         {"id":99,"at":\(t(9, 30)),"kind":"camera_on"},
         {"id":98,"at":\(t(9, 12)),"kind":"activity","activity":{"kind":"sudo","severity":"low",
          "summary":"me ran a command as root","detail":"/usr/sbin/softwareupdate --list"}},
         {"id":97,"at":\(t(8, 5)),"kind":"scan_completed","findings":3,"new":0,"resolved":0,"baseline":false}
        ]
        """
    }

    /// Six months of mostly calm days, a few worth a look, now and then an important one.
    @MainActor
    private static func days(today: UInt64, events: [LoggedEvent]) -> [DaySummary] {
        let cal = Calendar.current
        var out: [DaySummary] = []
        var seed: UInt64 = 42
        func next() -> UInt64 {
            seed = seed &* 6364136223846793005 &+ 1442695040888963407
            return seed >> 33
        }
        let todayDate = Date(timeIntervalSince1970: TimeInterval(today))
        for offset in (1...190).reversed() {
            guard let d = cal.date(byAdding: .day, value: -offset, to: todayDate) else { continue }
            let r = next()
            let weekend = cal.isDateInWeekend(d)
            if r % 11 == 0 || (weekend && r % 3 == 0) { continue } // switched off: no events
            let total = UInt32(weekend ? 4 + r % 10 : 12 + r % 30)
            var counts: [UInt32] = [total, 0, 0, 0, 0]
            if offset == 1 {
                // Yesterday: all calm.
            } else if r % 23 == 5 {
                counts[3] = 1; counts[2] = 1
            } else if r % 13 == 2 {
                counts[2] = 1 + UInt32(r % 2)
            } else if r % 4 == 0 {
                counts[1] = 1 + UInt32(r % 3)
            }
            counts[0] = total - counts[1...].reduce(0, +)
            let start = UInt64(d.timeIntervalSince1970)
            out.append(DaySummary(day: HistoryModel.dayString(start), start: start, events: total, counts: counts))
        }
        var counts: [UInt32] = [0, 0, 0, 0, 0]
        for e in events { counts[(e.severity ?? .info).rank] += 1 }
        out.append(DaySummary(day: HistoryModel.dayString(today), start: today, events: UInt32(events.count), counts: counts))
        return out
    }

    private static func pastFindings(now: UInt64) -> String {
        let day: UInt64 = 86_400
        return """
        [
         {"key":"health.remote_login||Remote Login (SSH) is on","severity":"medium","category":"system_health",
          "check":"health.remote_login","title":"Remote Login (SSH) is on",
          "detail":"Other computers can log in to this Mac over SSH. Fine if you use it; otherwise turn it off in System Settings → General → Sharing.",
          "first_seen":\(now - 9 * day),"last_seen":\(now - 6 * 3600),"acknowledged":false,"resolved_at":\(now - 6 * 3600)},
         {"key":"process.temp|/Users/me/Downloads/unzip-helper|unzip-helper runs from Downloads","severity":"high","category":"process",
          "check":"process.temp","title":"unzip-helper runs from your Downloads folder",
          "detail":"An unsigned program was running straight from Downloads. It has since stopped.",
          "path":"/Users/me/Downloads/unzip-helper","signing":{"kind":"unsigned","notarized":false},
          "first_seen":\(now - 12 * day),"last_seen":\(now - 12 * day + 1800),"acknowledged":false,"resolved_at":\(now - 12 * day + 2100)},
         {"key":"tcc.screen|/Applications/MeetNote.app|MeetNote can record your screen","severity":"low","category":"privacy",
          "check":"tcc.screen_capture","title":"MeetNote can record your screen",
          "detail":"Screen Recording permission. Signed: developer 3QF8L2M9TB, notarized [com.example.meetnote].",
          "path":"/Applications/MeetNote.app","signing":{"kind":"third_party","identifier":"com.example.meetnote","team_id":"3QF8L2M9TB","notarized":true},
          "first_seen":\(now - 40 * day),"last_seen":\(now - 18 * day),"acknowledged":true,"resolved_at":\(now - 18 * day)},
         {"key":"persistence.unverified|/Library/PrivilegedHelperTools/com.example.vpnhelper|Launch item com.example.vpnhelper","severity":"low",
          "category":"persistence","check":"persistence.unverified","title":"Launch item com.example.vpnhelper",
          "detail":"/Library/LaunchDaemons/com.example.vpnhelper.plist started as root at boot. Removed when the VPN app was uninstalled.",
          "path":"/Library/PrivilegedHelperTools/com.example.vpnhelper",
          "first_seen":\(now - 75 * day),"last_seen":\(now - 31 * day),"acknowledged":false,"resolved_at":\(now - 31 * day)}
        ]
        """
    }

    private static func changes(now: UInt64) -> String {
        let day: UInt64 = 86_400
        return """
        {"type":"changes","since":\(now - 7 * day),
         "new_findings":[
          {"key":"keylogger.event_tap|/Applications/QuickBar.app/Contents/MacOS/QuickBar|QuickBar can read your keystrokes",
           "severity":"medium","category":"keylogger","check":"keylogger.event_tap","title":"QuickBar can read your keystrokes",
           "detail":"Keyboard event tap on all apps, listen-only.","path":"/Applications/QuickBar.app/Contents/MacOS/QuickBar",
           "first_seen":\(now - 176 * 60),"last_seen":\(now - 140),"acknowledged":false},
          {"key":"persistence.script|\(helperPath)|Launch item com.example.helper","severity":"medium","category":"persistence",
           "check":"persistence.script","title":"Launch item com.example.helper","detail":"Starts when you log in: runs a script.",
           "path":"\(helperPath)","first_seen":\(now - 182 * 60),"last_seen":\(now - 140),"acknowledged":false},
          {"key":"persistence.launch_item|/Applications/Notely.app/Contents/MacOS/NotelyHelper|Launch item com.example.notely.helper","severity":"low",
           "category":"persistence","check":"persistence.launch_item","title":"Launch item com.example.notely.helper",
           "detail":"Starts when you log in.","path":"/Applications/Notely.app/Contents/MacOS/NotelyHelper",
           "first_seen":\(now - 4 * day),"last_seen":\(now - 140),"acknowledged":false},
          {"key":"tcc.microphone|/Applications/MeetNote.app|MeetNote can use your microphone","severity":"low","category":"privacy",
           "check":"tcc.microphone","title":"MeetNote can use your microphone","detail":"Microphone permission.",
           "path":"/Applications/MeetNote.app","first_seen":\(now - 2 * day),"last_seen":\(now - 140),"acknowledged":false}
         ],
         "resolved_findings":[
          {"key":"health.remote_login||Remote Login (SSH) is on","severity":"medium","category":"system_health",
           "check":"health.remote_login","title":"Remote Login (SSH) is on","detail":"Other computers could log in over SSH.",
           "first_seen":\(now - 9 * day),"last_seen":\(now - 6 * 3600),"acknowledged":false,"resolved_at":\(now - 6 * 3600)}
         ],
         "new_programs":[
          {"identity":"path:\(helperPath)","label":"PrintStudio Helper","first_seen":\(now - 180 * 60),"last_seen":\(now - 60 * 60),"runs":3},
          {"identity":"team:7XK2Q9M4LP:com.example.quickbar","label":"QuickBar","first_seen":\(now - 3 * day),"last_seen":\(now - 900),"runs":14}
         ]}
        """
    }

    private static func profile(now: UInt64) -> String {
        """
        {"type":"program_profile","path":"\(helperPath)","name":"PrintStudio Helper","exists":true,
         "signing":{"kind":"ad_hoc","notarized":false},
         "familiarity":{"identity":"path:\(helperPath)","label":"PrintStudio Helper","first_seen":\(now - 180 * 60),"last_seen":\(now - 60 * 60),"runs":3},
         "findings":[
          {"key":"persistence.script|\(helperPath)|Launch item com.example.helper","severity":"medium","category":"persistence",
           "check":"persistence.script","title":"Starts when you log in (com.example.helper)","detail":"Runs a script at login.",
           "path":"\(helperPath)","first_seen":\(now - 182 * 60),"last_seen":\(now - 140),"acknowledged":false}
         ],
         "past_findings":[],
         "events":[
          {"id":104,"at":\(now - 180 * 60),"kind":"activity","activity":{"kind":"process_started","severity":"low",
           "summary":"First run of PrintStudio Helper","process":"PrintStudio Helper","path":"\(helperPath)",
           "signing":{"kind":"ad_hoc","notarized":false}},"note":"That's the PrintStudio installer I ran. Fine.","reviewed_at":\(now - 170 * 60)},
          {"id":103,"at":\(now - 182 * 60),"kind":"new_finding","finding":
           {"key":"persistence.script|\(helperPath)|Launch item com.example.helper","severity":"medium","category":"persistence",
            "check":"persistence.script","title":"Launch item com.example.helper","detail":"Runs a script at login.",
            "path":"\(helperPath)","first_seen":\(now - 182 * 60),"last_seen":\(now - 182 * 60),"acknowledged":false}}
         ],
         "event_count":2}
        """
    }
}
