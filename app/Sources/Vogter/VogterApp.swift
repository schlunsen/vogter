import SwiftUI

@main
struct VogterApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuView()
                .environment(model)
        } label: {
            MenuBarLabel(model: model)
        }
        .menuBarExtraStyle(.window)

        Window("Vogter", id: "main") {
            MainWindow()
                .environment(model)
                .frame(minWidth: 720, minHeight: 460)
        }
    }
}

struct MenuBarLabel: View {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        HStack(spacing: 2) {
            Image(systemName: model.menuBarSymbol)
            if model.status?.av.microphoneInUse == true { Image(systemName: "mic.fill") }
            if model.status?.av.cameraInUse == true { Image(systemName: "video.fill") }
        }
        // The label always exists, so it's where notification clicks open the window.
        .onReceive(NotificationCenter.default.publisher(for: .vogterShowEvent)) { note in
            guard let id = note.object as? Int64 else { return }
            model.select(eventID: id)
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
    }
}
