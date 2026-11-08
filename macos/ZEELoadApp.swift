import AppKit
import SwiftUI
import UniformTypeIdentifiers

@main
@MainActor
struct ZEELoadApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = SessionModel()

    var body: some Scene {
        Window("极载 · ZEELoad", id: "dashboard") {
            Dashboard(model: model)
                .frame(minWidth: 820, minHeight: 650)
                .onAppear { delegate.model = model }
                .task { if model.report == nil { model.check() } }
        }
        .defaultSize(width: 930, height: 700)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var model: SessionModel?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        let waiting = model?.waitBeforeQuitting { sender.reply(toApplicationShouldTerminate: true) } ?? false
        return waiting ? .terminateLater : .terminateNow
    }
}

@MainActor
private struct Dashboard: View {
    @ObservedObject var model: SessionModel
    @State private var advanced = false
    @State private var dragging = false
    @State private var followLog = true
    @Environment(\.colorScheme) private var colorScheme

    private let gold = Color(red: 0.89, green: 0.73, blue: 0.44)

    var body: some View {
        VStack(spacing: 16) {
            banner
            HStack(alignment: .top, spacing: 14) {
                environmentCard.frame(maxWidth: .infinity)
                apkCard.frame(maxWidth: .infinity)
            }
            options
            actions
            console
        }
        .padding(20)
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(colorScheme == .dark ? gold : Color(red: 0.49, green: 0.34, blue: 0.12))
    }

    private var banner: some View {
        HStack(spacing: 14) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .interpolation(.high)
                .frame(width: 62, height: 62)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text("极载 · ZEELoad")
                    .font(.system(size: 26, weight: .semibold))
                    .foregroundStyle(.white)
                Text("macOS 车机侧载工具")
                    .font(.callout)
                    .foregroundStyle(.white.opacity(0.65))
            }
            Spacer()
            HStack(spacing: 7) {
                Circle().fill(badgeColor).frame(width: 7, height: 7).accessibilityHidden(true)
                Text(model.checking ? "环境检查中" : model.phase.rawValue)
                    .font(.callout.weight(.medium))
            }
            .padding(.horizontal, 11)
            .padding(.vertical, 7)
            .background(Color.white.opacity(0.08), in: Capsule())
            .foregroundStyle(.white)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background {
            RoundedRectangle(cornerRadius: 14).fill(
                LinearGradient(colors: [Color(white: 0.075), Color(red: 0.21, green: 0.15, blue: 0.08)],
                               startPoint: .leading, endPoint: .trailing)
            )
        }
    }

    private var badgeColor: Color {
        if model.checking { return gold }
        switch model.phase {
        case .ready, .update, .transfer: return Color(red: 0.61, green: 0.83, blue: 0.45)
        case .failed: return Color(red: 0.99, green: 0.61, blue: 0.42)
        case .authorizing, .starting, .stopping: return gold
        default: return .white.opacity(0.48)
        }
    }

    private var environmentCard: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack {
                Label("连接与环境", systemImage: "network").font(.headline)
                Spacer()
                Button("检查", action: model.check).disabled(!model.canEdit)
            }
            let report = model.report
            let mitmText: String = {
                guard let report else { return "等待检测" }
                switch report.mitmdump {
                case "missing": return "未找到"
                case "unsupported": return "缺少 --emudhra"
                default: return report.mitmdump
                }
            }()
            VStack(spacing: 8) {
                statusRow("共享接口", icon: "wifi", value: report?.bridge, empty: "未发现共享桥")
                statusRow("车机 IPv4", icon: "car.side", value: report?.car, empty: "尚未识别")
                statusRow("Mac 默认路由", icon: "arrow.up.right", value: report?.route, empty: "未发现默认路由")
                statusRow("mitmdump", icon: "terminal", value: mitmText, empty: "等待检测",
                          needsAttention: report?.mitmdumpReady == false)
            }
            Divider()
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text("车机请连接 Mac 共享的 Wi-Fi")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("共享设置", action: model.openSharing).buttonStyle(.link)
            }
        }
        .modifier(Card())
    }

    private func statusRow(_ title: String, icon: String, value: String?, empty: String,
                           needsAttention: Bool = false) -> some View {
        let warning = needsAttention || value?.isEmpty == true
        return HStack {
            Label(title, systemImage: icon)
                .font(.callout)
                .foregroundStyle(.secondary)
            Spacer(minLength: 10)
            Text(value.flatMap { $0.isEmpty ? nil : $0 } ?? (value == nil ? "等待检测" : empty))
                .font(.callout.monospacedDigit())
                .lineLimit(1)
                .truncationMode(.middle)
                .foregroundStyle(warning ? Color.orange : Color.primary)
                .textSelection(.enabled)
        }
    }

    private var apkCard: some View {
        VStack(alignment: .leading, spacing: 11) {
            HStack {
                Label("安装文件", systemImage: "shippingbox").font(.headline)
                Spacer()
                Button(model.apk == nil ? "选择 APK…" : "更换…", action: model.chooseAPK)
                    .disabled(!model.canEdit)
            }
            VStack(spacing: 7) {
                Image(systemName: model.apk == nil ? "arrow.down.doc" : "doc.badge.checkmark")
                    .font(.system(size: 27, weight: .light))
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                Text(model.apk?.lastPathComponent ?? "将 APK 拖到这里")
                    .font(.headline)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(model.apk == nil ? "也可点击右上方按钮选择文件" : ByteCountFormatter.string(fromByteCount: model.apkSize, countStyle: .file))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(10)
            .frame(maxWidth: .infinity, minHeight: 104)
            .background(Color.primary.opacity(dragging ? 0.07 : 0.025), in: RoundedRectangle(cornerRadius: 9))
            .overlay {
                RoundedRectangle(cornerRadius: 9)
                    .strokeBorder(Color.secondary.opacity(0.35), style: StrokeStyle(lineWidth: 1, dash: [5, 4]))
            }
            .onDrop(of: [UTType.fileURL.identifier], isTargeted: $dragging, perform: acceptDrop)
            .help(model.apk?.path ?? "拖入单个 APK 文件")
            Text("传输完成后，请在车机确认安装结果。")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .modifier(Card())
    }

    private func acceptDrop(_ providers: [NSItemProvider]) -> Bool {
        guard model.canEdit, providers.count == 1, let provider = providers.first else { return false }
        provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, _ in
            let url = (item as? URL) ?? (item as? Data).flatMap { URL(dataRepresentation: $0, relativeTo: nil) }
            if let url { Task { @MainActor in model.selectAPK(url) } }
        }
        return true
    }

    private var options: some View {
        DisclosureGroup("高级设置", isExpanded: $advanced) {
            VStack(alignment: .leading, spacing: 9) {
                HStack(spacing: 14) {
                    LabeledContent("共享接口") {
                        TextField("共享接口", text: $model.bridgeOverride, prompt: Text("自动检测，如 bridge100")).labelsHidden()
                    }
                    LabeledContent("车机 IPv4") {
                        TextField("车机 IPv4", text: $model.carOverride, prompt: Text("自动检测，如 192.168.2.10")).labelsHidden()
                    }
                }
                HStack(spacing: 12) {
                    Text("mitmdump")
                    Text(model.mitmdump.isEmpty ? "未找到可执行文件" : model.mitmdump)
                        .font(.caption.monospaced())
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                    Spacer()
                    Button("选择路径…", action: model.chooseMitmdump)
                }
                Text("车上无网线时，若共享来源里有 iPhone USB，可选它并共享到 Wi-Fi。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.top, 10)
            .disabled(!model.canEdit)
        }
        .padding(.horizontal, 4)
    }

    private var actions: some View {
        HStack(spacing: 10) {
            if model.checking || model.phase == .stopping || model.phase == .starting {
                ProgressView().controlSize(.small)
            }
            Text(model.detail)
                .font(.callout)
                .foregroundStyle(model.phase == .failed ? Color.orange : Color.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
            Spacer(minLength: 8)
            Button("恢复转发规则", action: model.restore).disabled(!model.canEdit)
                .help("检查并清理极载 Mac 的转发规则")
            Button("停止") { model.stop() }.disabled(!model.canStop)
            Button("开始侧载", action: model.start)
                .buttonStyle(.borderedProminent)
                .disabled(!model.canEdit || model.apk == nil)
        }
    }

    private var console: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack {
                Label("运行日志", systemImage: "text.alignleft").font(.headline)
                Spacer()
                Toggle("跟随日志", isOn: $followLog).toggleStyle(.checkbox)
                Button("复制") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(model.log, forType: .string)
                }
                .disabled(model.log.isEmpty)
                Button("日志目录", action: model.openLogs)
            }
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        Text(model.log.isEmpty ? "环境检查与侧载进度会显示在这里。" : model.log)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(model.log.isEmpty ? Color.secondary : Color.primary)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Color.clear.frame(height: 1).id("end")
                    }
                    .padding(10)
                }
                .onChange(of: model.log) { _ in if followLog { proxy.scrollTo("end", anchor: .bottom) } }
            }
            .frame(minHeight: 155, maxHeight: .infinity)
            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        }
        .modifier(Card())
    }
}

private struct Card: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(13)
            .frame(maxWidth: .infinity, alignment: .topLeading)
            .background(Color.primary.opacity(0.027), in: RoundedRectangle(cornerRadius: 11))
            .overlay { RoundedRectangle(cornerRadius: 11).strokeBorder(Color.primary.opacity(0.08)) }
    }
}
