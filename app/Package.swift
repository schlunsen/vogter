// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Vogter",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "Vogter",
            path: "Sources/Vogter",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "VogterTests",
            dependencies: ["Vogter"],
            path: "Tests/VogterTests",
            resources: [.copy("Fixtures")],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
