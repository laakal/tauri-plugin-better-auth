// swift-tools-version:5.3

import PackageDescription

let package = Package(
  name: "tauri-plugin-better-auth",
  platforms: [
    .macOS(.v10_15),
    .iOS(.v13),
  ],
  products: [
    .library(
      name: "tauri-plugin-better-auth",
      type: .static,
      targets: ["tauri-plugin-better-auth"])
  ],
  dependencies: [
    // Copied here by the crate's build script.
    .package(name: "Tauri", path: "../.tauri/tauri-api")
  ],
  targets: [
    .target(
      name: "tauri-plugin-better-auth",
      dependencies: [
        .byName(name: "Tauri")
      ],
      path: "Sources")
  ]
)
