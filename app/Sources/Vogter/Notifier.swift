import Foundation
import UserNotifications

/// Posts user notifications for events that deserve attention.
final class Notifier {
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
        let request = UNNotificationRequest(identifier: "vogter-\(event.id)", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
