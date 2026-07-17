// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ArcBoxVZShim",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "ArcBoxVZShim", type: .static, targets: ["ArcBoxVZShim"])
    ],
    targets: [
        .target(
            name: "ArcBoxVZShim",
            path: "Sources/ArcBoxVZShim",
            swiftSettings: [
                .swiftLanguageMode(.v5)
            ],
            linkerSettings: [
                // Recorded as autolink metadata; the authoritative link arg is
                // emitted by arcbox-vz's build.rs (explicit -framework).
                .linkedFramework("Virtualization")
            ]
        )
    ]
)
