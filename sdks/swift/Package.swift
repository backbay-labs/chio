// swift-tools-version: 5.7

import PackageDescription

// TRAJECTORY-3.1 reclassification: M07 is design-only and the
// `ChioKernel.xcframework` binary artifact is not produced in this
// trajectory. The `binaryTarget` reference has been removed pending
// the trajectory-4 real-attestation deliverable. See
// `sdks/swift/README.md` for the deferral note.

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
        .systemLibrary(
            name: "ChioFFI",
            path: "Sources/ChioFFI"
        ),
        .target(
            name: "Chio",
            dependencies: [
                "ChioFFI"
            ]
        ),
        .testTarget(
            name: "ChioTests",
            dependencies: ["Chio"]
        )
    ]
)
