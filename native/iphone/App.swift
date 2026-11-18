import CryptoKit
import Security
import SwiftUI
import UniformTypeIdentifiers

private enum HostError: Error { case unavailable }

private func bridge(_ object: [String: Any]) throws -> [String: Any] {
    let input = try JSONSerialization.data(withJSONObject: object)
    guard let text = String(data: input, encoding: .utf8) else { throw HostError.unavailable }
    let pointer = text.withCString { praefectus_iphone_call($0) }!
    defer { praefectus_iphone_free(pointer) }
    let output = Data(String(cString: pointer).utf8)
    guard let value = try JSONSerialization.jsonObject(with: output) as? [String: Any],
          value["ok"] as? Bool == true,
          let result = value["data"] as? [String: Any] else { throw HostError.unavailable }
    return result
}

private enum Credentials {
    static func load(_ name: String) -> Data? {
        var output: CFTypeRef?
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "praefectus.iphone", kSecAttrAccount as String: name,
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        guard SecItemCopyMatching(query as CFDictionary, &output) == errSecSuccess else { return nil }
        return output as? Data
    }

    static func save(_ name: String, _ data: Data) throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "praefectus.iphone", kSecAttrAccount as String: name]
        let attributes: [String: Any] = [kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            guard SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil) == errSecSuccess
            else { throw HostError.unavailable }
        } else if status != errSecSuccess { throw HostError.unavailable }
    }

    static func signingKey() throws -> Curve25519.Signing.PrivateKey {
        if let stored = load("authority") { return try Curve25519.Signing.PrivateKey(rawRepresentation: stored) }
        let key = Curve25519.Signing.PrivateKey()
        try save("authority", key.rawRepresentation)
        return key
    }
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
    init?(hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        var index = hex.startIndex
        while index < hex.endIndex {
            let end = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<end], radix: 16) else { return nil }
            bytes.append(byte)
            index = end
        }
        self.init(bytes)
    }
}

@MainActor
private final class PhoneHost: ObservableObject {
    @Published var status = "Not connected. Import a real RemotePairing plist and enable your loopback VPN."
    @Published var busy = false
    @Published var connected = false
    @Published var screen: UIImage?
    private var coordinates: [String: Any]?
    private let queue = DispatchQueue(label: "praefectus.phone-host")
    private var background = UIBackgroundTaskIdentifier.invalid
    private var pending: DispatchWorkItem?
    private var generation = UUID()
    private var authorizedUntil: Date?
    private var revoked = false
    private var directory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Praefectus", isDirectory: true)
    }

    func importPairing(_ url: URL) {
        do {
            let granted = url.startAccessingSecurityScopedResource()
            defer { if granted { url.stopAccessingSecurityScopedResource() } }
            let file = try FileHandle(forReadingFrom: url)
            defer { try? file.close() }
            let data = try file.read(upToCount: 65537) ?? Data()
            guard data.count <= 65536 else { throw HostError.unavailable }
            // Normalize binary plists to XML; the Rust bridge never logs credentials.
            let plist = try PropertyListSerialization.propertyList(from: data, format: nil)
            let xml = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            try Credentials.save("pairing", xml)
            status = "Pairing stored in this device’s Keychain. Connect when the VPN is ready."
        } catch { status = "Could not import pairing. No credentials were changed." }
    }

    func connect(port: String) {
        guard !busy else { return }
        connected = false
        authorizedUntil = nil
        coordinates = nil
        screen = nil
        do {
            guard let port = UInt16(port), port > 0,
                  let data = Credentials.load("pairing"), let pairing = String(data: data, encoding: .utf8)
            else { throw HostError.unavailable }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication])
            let key = try Credentials.signingKey()
            let path = directory.path
            run(delay: 0) {
                _ = try bridge(["command": "connect", "port": port, "pairing_plist": pairing,
                    "public_key": key.publicKey.rawRepresentation.hex, "directory": path])
                return ("Connected. Local session execution is enabled for 15 minutes without per-action approval.", nil, true)
            }
        } catch { status = "A pairing record and valid RemotePairing port are required." }
    }

    func observe() {
        run(delay: 3) {
            let coordinates = try bridge(["command": "observe"])
            return ("Screen captured. Targets expire after 30 seconds; changed screens are rejected.", coordinates, nil)
        }
    }

    func discover() {
        run(delay: 0) {
            let result = try bridge(["command": "discover"])
            let apps = result["applications"] as? [String] ?? []
            let session = result["session"] as? [String: Any] ?? [:]
            let services = session["services"] as? [String] ?? []
            return ("Discovered \(services.count) services and \(apps.count) apps. Native input advertised: \(session["native_input"] as? Bool ?? false).", nil, nil)
        }
    }

    // The host's session lease permits signing; the executor never owns that policy.
    func authorize(operation: String, x: String, y: String, endX: String, endY: String, text: String) {
        do {
            guard connected, let authorizedUntil, authorizedUntil > Date() else {
                revoke()
                status = "Session authorization expired. Reconnect to enable execution."
                return
            }
            let action: [String: Any]
            var target: [String: Any] = ["kind": "none"]
            if operation != "Launch app" { target = try point(x, y) }
            switch operation {
            case "Tap": action = ["kind": "click", "button": "left", "count": 1, "allow_coordinate_fallback": false]
            case "Swipe": action = ["kind": "drag", "button": "left", "to": try point(endX, endY)]
            case "Scroll down": action = ["kind": "scroll", "direction": "down", "amount": 1]
            case "Paste text": action = ["kind": "paste", "text": text]
            case "Home": action = ["kind": "press", "key": "home", "count": 1, "delay_ms": NSNull()]
            default: action = ["kind": "application", "operation": "launch", "name": text]
            }
            let key = try Credentials.signingKey()
            run(delay: 3) {
                guard authorizedUntil > Date() else { throw HostError.unavailable }
                let prepared = try bridge(["command": "prepare", "action": action, "target": target,
                    "not_after_ms": Int64(authorizedUntil.timeIntervalSince1970 * 1000)])
                guard var request = prepared["request"] as? [String: Any],
                      var authority = request["authority"] as? [String: Any],
                      let encoded = prepared["signing_bytes"] as? String, let bytes = Data(hex: encoded)
                else { throw HostError.unavailable }
                authority["signature"] = try key.signature(for: bytes).hex
                request["authority"] = authority
                let report = try bridge(["command": "execute", "request": request])
                let acknowledgements = report["acknowledgements"] as? [[String: Any]] ?? []
                let state = acknowledgements.last?["state"] as? [String: Any] ?? [:]
                let terminal = state["terminal"] as? [String: Any] ?? [:]
                let kind = terminal["kind"] as? String ?? "unknown"
                return ("Result: \(kind). Success is unverified delivery, not proof of the intended app effect. Never automatically retry an unknown outcome.", nil, nil)
            }
        } catch { status = "Observe first and choose valid screenshot pixel coordinates." }
    }

    private func point(_ x: String, _ y: String) throws -> [String: Any] {
        guard let coordinates, let x = Int(x), let y = Int(y),
              let displays = coordinates["displays"] as? [[String: Any]], let display = displays.first,
              let width = display["width"] as? Int, let height = display["height"] as? Int,
              (0..<width).contains(x), (0..<height).contains(y) else { throw HostError.unavailable }
        return ["kind": "coordinates", "x": x, "y": y, "display_id": "iphone-primary",
            "display_geometry_hash": coordinates["display_geometry_hash"]!,
            "snapshot_id": coordinates["snapshot_id"]!, "snapshot_content_hash": coordinates["snapshot_content_hash"]!]
    }

    func cancel() {
        praefectus_iphone_cancel()
        status = "Stop requested. If dispatch began, inspect the phone before retrying."
    }

    func revoke() {
        cancel()
        revoked = true
        authorizedUntil = nil
        connected = false
        coordinates = nil
        screen = nil
        queue.async { _ = try? bridge(["command": "disconnect"]) }
        status = "Session revoked. Inspect any interrupted effect before reconnecting."
    }

    private func endBackgroundTask() {
        let task = background
        background = .invalid
        if task != .invalid { UIApplication.shared.endBackgroundTask(task) }
    }

    private func run(delay: TimeInterval, _ work: @escaping () throws -> (String, [String: Any]?, Bool?)) {
        guard !busy else { return }
        busy = true
        revoked = false
        praefectus_iphone_begin()
        generation = UUID()
        let id = generation
        background = UIApplication.shared.beginBackgroundTask(withName: "One authorized phone operation") { [weak self] in
            self?.revoke()
            self?.endBackgroundTask()
        }
        status = delay > 0 ? "Switch to the target app now. Running in 3 seconds…" : "Connecting to phone services…"
        // A cancelled delay still runs to completion with a cancelled token.
        let item = DispatchWorkItem { [weak self] in
            guard let self else { return }
            let result = Result { try work() }
            DispatchQueue.main.async {
                guard self.generation == id else { return }
                self.busy = false
                self.pending = nil
                switch self.revoked ? .failure(HostError.unavailable) : result {
                case .success(let (message, coordinates, connected)):
                    self.status = message
                    if let connected {
                        self.connected = connected
                        self.authorizedUntil = connected ? Date().addingTimeInterval(15 * 60) : nil
                    }
                    if let coordinates {
                        self.coordinates = coordinates
                        self.screen = UIImage(contentsOfFile: self.directory.appendingPathComponent("screen.png").path)
                    }
                case .failure:
                    self.status = "Operation unavailable. Verify VPN, pairing, developer image and services; reconnect after a transport failure."
                }
                self.endBackgroundTask()
            }
        }
        pending = item
        queue.asyncAfter(deadline: .now() + delay, execute: item)
    }
}

@main
struct PraefectusPhoneApp: App {
    var body: some Scene { WindowGroup { PhoneView() } }
}

private struct PhoneView: View {
    @StateObject private var host = PhoneHost()
    @State private var importing = false
    @State private var port = "49152"
    @State private var operation = "Tap"
    @State private var x = ""
    @State private var y = ""
    @State private var endX = ""
    @State private var endY = ""
    @State private var text = ""
    @State private var confirmEachAction = false
    @State private var confirming = false
    var body: some View {
        NavigationStack {
            Form {
                Section("Experimental · CoreDevice") {
                    Text("Requires real device pairing, a mounted developer image and a loopback VPN. No computer relay runs during an operation.")
                    Text("Physical-device control has not been verified.").font(.caption)
                    Text(host.status).accessibilityIdentifier("phone-status")
                }
                Section("Device setup") {
                    Button("Import pairing plist") { importing = true }.disabled(host.busy)
                    LabeledContent("RemotePairing port") {
                        TextField("Port", text: $port).keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing).accessibilityLabel("RemotePairing port")
                    }
                    Button("Connect to this iPhone") { host.connect(port: port) }.disabled(host.busy)
                    Button("Discover services and apps") { host.discover() }.disabled(host.busy || !host.connected)
                }
                Section("Observe") {
                    Button("Observe after 3 seconds") { host.observe() }.disabled(host.busy || !host.connected)
                    if let image = host.screen { Image(uiImage: image).resizable().scaledToFit().accessibilityLabel("Last device screenshot") }
                    Text("Switch to the target app during the delay. Return here to select pixels, then switch back during the action delay. Screens must still match.").font(.caption)
                }
                Section("Session execution") {
                    Text("Connecting enables local execution for 15 minutes. Each request is still host-signed. Stop and revoke ends the session.").font(.caption)
                    Toggle("Confirm each action", isOn: $confirmEachAction).disabled(host.busy)
                    Picker("Operation", selection: $operation) {
                        ForEach(["Tap", "Swipe", "Scroll down", "Paste text", "Home", "Launch app"], id: \.self) { Text($0) }
                    }.accessibilityIdentifier("operation-picker")
                    if operation != "Launch app" {
                        TextField("X (screenshot pixels)", text: $x).keyboardType(.numberPad)
                        TextField("Y (screenshot pixels)", text: $y).keyboardType(.numberPad)
                    }
                    if operation == "Swipe" {
                        TextField("End X", text: $endX).keyboardType(.numberPad)
                        TextField("End Y", text: $endY).keyboardType(.numberPad)
                    }
                    if operation == "Paste text" || operation == "Launch app" {
                        TextField(operation == "Launch app" ? "Bundle identifier" : "Text to paste (replaces clipboard)", text: $text)
                            .autocorrectionDisabled().textInputAutocapitalization(.never)
                    }
                    Button("Run after 3 seconds") {
                        if confirmEachAction { confirming = true }
                        else { execute() }
                    }.disabled(host.busy || !host.connected)
                    Text("Per-action confirmation is off by default. The host signs within the active session using a device-only Keychain key; it is not an autonomous AI planner.").font(.caption)
                }
                Button("Stop and revoke", role: .destructive) { host.revoke() }.disabled(!host.busy && !host.connected)
            }
            .navigationTitle("Praefectus iPhone")
            .confirmationDialog("Run this action?", isPresented: $confirming, titleVisibility: .visible) {
                Button("Authorize this action") { execute() }
            }
            .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
                if case .success(let url) = result { host.importPairing(url) }
            }
        }
    }

    private func execute() {
        host.authorize(operation: operation, x: x, y: y, endX: endX, endY: endY, text: text)
    }
}
