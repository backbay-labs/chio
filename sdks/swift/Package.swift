// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "Chio",
    platforms: [
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "Chio",
            targets: ["Chio"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "ChioKernel",
            path: "Frameworks/ChioKernel.xcframework"
        ),
        .systemLibrary(
            name: "ChioFFI",
            path: "Sources/ChioFFI"
        ),
        .target(
            name: "Chio",
            dependencies: [
                "ChioKernel",
                "ChioFFI"
            ]
        ),
        .testTarget(
            name: "ChioTests",
            dependencies: ["Chio"]
        )
    ]
)
