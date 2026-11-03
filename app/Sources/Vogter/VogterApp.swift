import SwiftUI

/// `Vogter --render-screenshots <dir>` writes README screenshots from demo data and
/// exits without starting the app; anything else runs the menu bar app.
@main
enum Entry {
    static func main() {
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--render-screenshots") {
            guard i + 1 < args.count else {
                FileHandle.standardError.write(Data("usage: Vogter --render-screenshots <output-dir>\n".utf8))
                exit(2)
            }
            let dir = URL(fileURLWithPath: args[i + 1], isDirectory: true)
            let ok = MainActor.assumeIsolated { Screenshots.render(to: dir) }
            exit(ok ? 0 : 1)
        }
        VogterApp.main()
    }
}

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
