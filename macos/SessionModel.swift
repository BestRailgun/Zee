import AppKit
import Darwin
import Foundation
import SwiftUI
import UniformTypeIdentifiers

struct EnvironmentReport {
    var bridge = ""
    var car = ""
    var route = ""
    var mitmdump = "missing"
    var addon = false
    var portBusy = false

    var mitmdumpReady: Bool { !mitmdump.isEmpty && mitmdump != "missing" && mitmdump != "unsupported" }

    init(_ output: String) {
        for line in output.split(separator: "\n") where line.hasPrefix("[gui-env] ") {
            let pair = line.dropFirst("[gui-env] ".count).split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2 else { continue }
            let value = String(pair[1])
            switch pair[0] {
            case "bridge": bridge = value
            case "car": car = value
            case "route": route = value
            case "mitmdump": mitmdump = value
            case "addon": addon = value == "present"
            case "port": portBusy = value == "busy"
            default: break
            }
        }
    }
}

@MainActor
final class SessionModel: ObservableObject {
    enum Phase: String {
        case idle = "待开始"
        case authorizing = "等待授权"
        case starting = "正在启动"
        case ready = "代理已监听"
        case update = "已识别更新"
        case transfer = "APK 已开始传输"
        case stopping = "正在停止"
        case stopped = "已停止"
        case failed = "需要处理"
    }

    private enum Action: String { case run, restore }

    private struct Options {
        let apk: String
        let bridge: String
        let car: String

        var environment: [String: String] {
            ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
             "LANG": "en_US.UTF-8",
             "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
             "ZEEKR_GUI": "1", "ZEEKR_IFACE": bridge, "ZEEKR_CAR_IP": car]
        }
    }

    private struct ActiveSession {
        let action: Action
        let directory: URL
        let process: Process
        let activity: FileHandle
    }

    @Published var bridgeOverride = ""
    @Published var carOverride = ""
    @Published private(set) var apk: URL?
    @Published private(set) var apkSize: Int64 = 0
    @Published private(set) var report: EnvironmentReport?
    @Published private(set) var phase: Phase = .idle
    @Published private(set) var detail = "连接车机热点并选择 APK 后，即可开始。"
    @Published private(set) var log = ""
    @Published private(set) var checking = false

    let logs = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/ZEELoad", isDirectory: true)
    private let resources = Bundle.main.resourceURL ?? Bundle.main.bundleURL
    private var diagnostic: Process?
    private var active: ActiveSession?
    private var pollTimer: Timer?
    private var pending = Data()
    private var started = false
    private var restored = false
    private var lastError = ""
    private var quitReply: (() -> Void)?

    var canEdit: Bool { !checking && active == nil }
    var canStop: Bool { active?.action == .run && phase != .stopping }

    init() {
        // Remove the executable path stored by earlier releases.
        UserDefaults.standard.removeObject(forKey: "mitmdumpPath")
    }

    func chooseAPK() {
        let panel = NSOpenPanel()
        panel.title = "选择要安装的 APK"
        panel.allowedContentTypes = [UTType(filenameExtension: "apk") ?? .data]
        panel.canChooseDirectories = false
        if panel.runModal() == .OK, let url = panel.url { selectAPK(url) }
    }

    func selectAPK(_ url: URL) {
        guard canEdit else { return }
        let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard url.isFileURL, url.pathExtension.lowercased() == "apk",
              values?.isRegularFile == true, let size = values?.fileSize, size > 0 else {
            detail = "请选择一个可读取的 APK 文件。"
            return
        }
        apk = url.standardizedFileURL
        apkSize = Int64(size)
        detail = "APK 已选定。开始前将重新检查网络和工具。"
    }

    func check() { check(startAfter: false) }
    func start() { check(startAfter: true) }

    private func check(startAfter: Bool) {
        guard canEdit else { return }
        let bridge = bridgeOverride.trimmingCharacters(in: .whitespacesAndNewlines)
        let car = carOverride.trimmingCharacters(in: .whitespacesAndNewlines)
        var address = in_addr()
        guard bridge.isEmpty || bridge.range(of: #"^bridge[0-9]+$"#, options: .regularExpression) != nil else {
            fail("共享接口格式应类似 bridge100。")
            return
        }
        guard car.isEmpty || inet_pton(AF_INET, car, &address) == 1 else {
            fail("请填入车机的 IPv4 地址。")
            return
        }
        let options = Options(apk: apk?.path ?? "", bridge: bridge, car: car)
        if startAfter && !FileManager.default.isReadableFile(atPath: options.apk) {
            fail("APK 已移动或无法读取，请重新选择。")
            return
        }

        let file = FileManager.default.temporaryDirectory.appendingPathComponent("zeeload-check-\(UUID().uuidString).log")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [resources.appendingPathComponent("scripts/check-environment.sh").path]
        process.environment = options.environment
        process.terminationHandler = { [weak self] process in
            let status = process.terminationStatus
            let output = String(decoding: (try? Data(contentsOf: file)) ?? Data(), as: UTF8.self)
            try? FileManager.default.removeItem(at: file)
            Task { @MainActor in self?.checked(output, status: status, startAfter: startAfter, options: options) }
        }
        checking = true
        phase = .idle
        detail = "正在检查共享接口、车机地址和 mitmdump…"
        do {
            try launch(process, capturing: file)
            diagnostic = process
        } catch {
            try? FileManager.default.removeItem(at: file)
            checking = false
            fail("无法启动环境检查。\n\(error.localizedDescription)")
        }
    }

    private func checked(_ output: String, status: Int32, startAfter: Bool, options: Options) {
        diagnostic = nil
        checking = false
        append("\n── 环境检查 ──\n")
        append(output.split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !$0.hasPrefix("[gui-env] ") }.joined(separator: "\n"))
        let report = EnvironmentReport(output)
        self.report = report

        guard status == 0 && report.addon else { fail("环境检查失败，请查看运行日志。"); return }
        guard report.mitmdumpReady else { fail("内置 mitmdump 检查失败，请重新下载并解压 ZEELoad.app。"); return }
        guard !report.bridge.isEmpty else { fail("未检测到共享接口。请打开互联网共享，并让车机连上 Mac 的 Wi-Fi。"); return }
        guard !report.portBusy else { fail("18080 端口已占用，请结束之前的代理会话。"); return }
        if startAfter {
            begin(.run, options: options)
        } else if report.car.isEmpty {
            detail = "尚未识别车机 IP。可在高级设置填入车机网络详情中的 IPv4 地址。"
        } else {
            detail = "已检测到共享接口和车机地址，可以开始。"
        }
    }

    func restore() {
        guard canEdit else { return }
        begin(.restore, options: Options(apk: "", bridge: "", car: ""))
    }

    private func begin(_ action: Action, options: Options) {
        let prefix = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let directory = logs.appendingPathComponent("\(prefix)-\(UUID().uuidString.prefix(8))", isDirectory: true)
        let activity = directory.appendingPathComponent("activity.log")
        let response = directory.appendingPathComponent("authorization.log")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = [resources.appendingPathComponent("macos/authorize.scpt").path,
                             resources.appendingPathComponent("macos/session.sh").path,
                             action.rawValue, String(getuid()), String(getpid()), directory.path,
                             options.apk, options.bridge, options.car]
        process.terminationHandler = { [weak self] process in
            let status = process.terminationStatus
            Task { @MainActor in self?.ended(status: status, response: response) }
        }

        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try Data().write(to: activity, options: .withoutOverwriting)
            let reader = try FileHandle(forReadingFrom: activity)
            active = ActiveSession(action: action, directory: directory, process: process, activity: reader)
            pending = Data()
            started = false
            restored = false
            lastError = ""
            phase = .authorizing
            detail = action == .run ? "请在 macOS 对话框中授权启动。" : "请在 macOS 对话框中授权恢复转发规则。"
            append(action == .run ? "\n── 启动会话 ──\n" : "\n── 恢复转发规则 ──\n")
            try launch(process, capturing: response)
            pollTimer = Timer.scheduledTimer(withTimeInterval: 0.3, repeats: true) { [weak self] _ in
                Task { @MainActor in self?.pollActivity() }
            }
        } catch {
            try? active?.activity.close()
            active = nil
            fail("无法启动授权进程。\n\(error.localizedDescription)")
        }
    }

    @discardableResult
    func stop() -> Bool {
        guard let active, active.action == .run else { return false }
        if phase == .stopping { return true }
        do {
            try Data().write(to: active.directory.appendingPathComponent("stop"), options: .atomic)
            phase = .stopping
            detail = "正在停止代理并检查转发规则，请稍候。"
            return true
        } catch {
            detail = "无法发送停止请求。退出应用会触发会话清理。"
            append("\n\(error.localizedDescription)\n")
            return false
        }
    }

    func waitBeforeQuitting(_ reply: @escaping () -> Void) -> Bool {
        guard let active else { return false }
        if active.action == .run && !stop() { return false }
        quitReply = reply
        return true
    }

    private func ended(status: Int32, response: URL) {
        pollTimer?.invalidate()
        pollTimer = nil
        pollActivity(drain: true)
        if !pending.isEmpty { consume(String(decoding: pending, as: UTF8.self)) }
        let output = ((try? String(contentsOf: response, encoding: .utf8)) ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let action = active?.action
        try? active?.activity.close()
        active = nil

        if output == "cancelled" || (status == 0 && action == .run && !started) {
            phase = .idle
            detail = "已取消启动或管理员授权。"
        } else if status == 0 && restored {
            phase = .stopped
            detail = action == .restore ? "已确认极载 Mac 的转发规则清空。" : "代理已退出，极载 Mac 的转发规则已清空。"
        } else {
            if !output.isEmpty && output != "completed" { append("\n\(output)\n") }
            fail(lastError.isEmpty ? "会话异常结束，请查看运行日志。" : lastError)
        }
        let reply = quitReply
        quitReply = nil
        reply?()
    }

    private func pollActivity(drain: Bool = false) {
        guard let handle = active?.activity else { return }
        var reads = 0
        while drain || reads < 4 {
            guard let bytes = try? handle.read(upToCount: 65_536), !bytes.isEmpty else { return }
            pending.append(bytes)
            if let end = pending.lastIndex(of: 10) {
                consume(String(decoding: pending.prefix(through: end), as: UTF8.self))
                pending.removeSubrange(...end)
            } else if pending.count > 65_536 {
                consume(String(decoding: pending, as: UTF8.self))
                pending.removeAll(keepingCapacity: true)
            }
            reads += 1
        }
    }

    private func consume(_ text: String) {
        var visible: [Substring] = []
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            if line == "[gui-session] start" {
                started = true
                if phase == .authorizing {
                    phase = .starting
                    detail = "已授权，正在验证车机地址和代理状态。"
                }
                continue
            }
            if line.hasPrefix("[gui-session] car=") {
                report?.car = String(line.dropFirst("[gui-session] car=".count))
                continue
            }
            if line.hasPrefix("[gui-session] 已确认") { restored = true }
            if line.hasPrefix("错误：") { lastError = String(line.dropFirst("错误：".count)) }
            visible.append(line)
            guard active?.action == .run && phase != .stopping else { continue }
            if line.hasPrefix("[ok] mitmdump 已启动") && phase == .starting {
                phase = .ready
                detail = "请在车机应用商店打开应用详情页。"
            } else if line.contains("[inject-update] 已为") && phase != .transfer {
                phase = .update
                detail = "车机已收到更新条目，请在车机点更新。"
            } else if line.contains("[replace-apk] 以 ") {
                phase = .transfer
                detail = "已开始发送 APK。请在车机确认安装结果，再点击停止。"
            }
        }
        append(visible.joined(separator: "\n"))
    }

    private func append(_ text: String) {
        log.append(text)
        if log.count > 42_000 { log = String(log.suffix(35_000)) }
    }

    private func fail(_ message: String) {
        phase = .failed
        detail = message
    }

    func openLogs() {
        do {
            try FileManager.default.createDirectory(at: logs, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            NSWorkspace.shared.open(logs)
        } catch { detail = error.localizedDescription }
    }

    func openSharing() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.Sharing-Settings.extension") else { return }
        NSWorkspace.shared.open(url)
    }

    private func launch(_ process: Process, capturing url: URL) throws {
        try Data().write(to: url, options: .withoutOverwriting)
        let output = try FileHandle(forWritingTo: url)
        defer { try? output.close() }
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = output
        try process.run()
    }
}
