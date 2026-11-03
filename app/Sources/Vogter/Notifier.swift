import Foundation
import UserNotifications

extension Notification.Name {
    /// Posted with `object: eventID (Int64)` when the user clicks an alert notification.
    static let vogterShowEvent = Notification.Name("vogterShowEvent")
}

/// Posts user notifications for events that deserve attention, and routes
/// clicks on them back into the app.
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    override init() {
        super.init()
        UNUserNotificationCenter.current().delegate = self
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        if let id = response.notification.request.content.userInfo["eventID"] as? Int64 {
            DispatchQueue.main.async { NotificationCenter.default.post(name: .vogterShowEvent, object: id) }
        }
        completionHandler()
    }

    /// Show banners even while Vogter is the active app.
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }

    /// New findings below this severity don't notify.
    var minimumSeverity: Severity = .medium

    func requestAuthorization() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, error in
            if let error { NSLog("vogter: notification authorization failed: \(error)") }
            else if !granted { NSLog("vogter: notifications not allowed") }
        }
    }

    func notify(for event: LoggedEvent) {
        let content = UNMutableNotificationContent()
        switch event.kind {
        case let .newFinding(f) where f.severity >= minimumSeverity:
            content.title = "\(f.severity.label): \(f.title)"
            content.body = f.detail
            content.sound = f.severity >= .high ? .default : nil
        case let .activity(a) where a.kind == "away_summary" && a.severity > .info:
            content.title = a.summary
            content.body = a.detail ?? ""
        case let .activity(a) where a.severity >= minimumSeverity:
            content.title = "\(a.severity.label): \(a.summary)"
            content.body = a.detail ?? ""
            content.sound = a.severity >= .high ? .default : nil
        case let .microphoneOn(clients):
            content.title = "Microphone is on"
            let who = clients.map(\.name).joined(separator: ", ")
            content.body = who.isEmpty ? "An app started recording audio." : "Used by \(who)."
        case .cameraOn:
            content.title = "Camera is on"
            content.body = "An app started using the camera."
        default:
            return
        }
        content.userInfo = ["eventID": event.id]
        let request = UNNotificationRequest(identifier: "vogter-\(event.id)", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
