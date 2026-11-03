import Foundation

/// A newline-delimited JSON connection to vogterd over a Unix socket.
/// Reads run on a background thread; callbacks are delivered on the main queue.
final class DaemonConnection {
    private let fd: Int32
    private let writeQueue = DispatchQueue(label: "vogter.daemon.write")
    private var closed = false

    /// Sockets to try, in order. Matches `vogter_ipc::socket_candidates`.
    static var candidates: [String] {
        var paths: [String] = []
        if let env = ProcessInfo.processInfo.environment["VOGTER_SOCKET"] { paths.append(env) }
        paths.append("/var/run/vogter.sock")
        paths.append(NSHomeDirectory() + "/Library/Application Support/Vogter/vogter.sock")
        return paths
    }

    static func connectAny() -> (DaemonConnection, String)? {
        for path in candidates {
            if let c = DaemonConnection(path: path) { return (c, path) }
        }
        return nil
    }

    init?(path: String) {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard path.utf8.count < capacity else { Darwin.close(fd); return nil }
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            buf.copyBytes(from: path.utf8)
            buf[path.utf8.count] = 0
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else { Darwin.close(fd); return nil }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        self.fd = fd
    }

    deinit { close() }

    func close() {
        guard !closed else { return }
        closed = true
        shutdown(fd, SHUT_RDWR)
        Darwin.close(fd)
    }

    func send(_ request: [String: Any]) {
        guard var data = try? JSONSerialization.data(withJSONObject: request) else { return }
        data.append(0x0A)
        writeQueue.async { [fd] in
            data.withUnsafeBytes { raw in
                var offset = 0
                while offset < raw.count {
                    let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
                    if n <= 0 { return }
                    offset += n
                }
            }
        }
    }

    /// Start reading. `onMessage` per decoded line, `onClose` once at EOF/error.
    func start(onMessage: @escaping (DaemonMessage) -> Void, onClose: @escaping () -> Void) {
        let fd = self.fd
        let thread = Thread {
            let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase
            var buffer = Data()
            var chunk = [UInt8](repeating: 0, count: 64 * 1024)
            while true {
                let n = read(fd, &chunk, chunk.count)
                if n <= 0 { break }
                buffer.append(contentsOf: chunk[0..<n])
                while let nl = buffer.firstIndex(of: 0x0A) {
                    let line = buffer[buffer.startIndex..<nl]
                    buffer.removeSubrange(buffer.startIndex...nl)
                    do {
                        let msg = try decoder.decode(DaemonMessage.self, from: line)
                        DispatchQueue.main.async { onMessage(msg) }
                    } catch {
                        NSLog("vogter: undecodable message: \(error)")
                    }
                }
            }
            DispatchQueue.main.async { onClose() }
        }
        thread.name = "vogter.daemon.read"
        thread.start()
    }
}
