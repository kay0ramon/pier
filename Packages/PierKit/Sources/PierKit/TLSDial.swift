import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOTLS
import NIOWebSocket

/// Where a box's relay is: "HOST:PORT", the relay's own TCP, or a `ws://` / `wss://` URL, its protocol inside a
/// WebSocket, behind an HTTPS front (the Pier tunnel). docs/PROTOCOL.md §10.
struct RelayEndpoint: Sendable, Hashable {
    let host: String
    let port: Int
    let webSocket: Bool
    let tls: Bool
    /// The WebSocket's path, and the Host header.
    let path: String
    let authority: String

    static func parse(_ s: String) -> RelayEndpoint? {
        if s.hasPrefix("wss://") || s.hasPrefix("ws://") {
            guard let u = URLComponents(string: s), let host = u.host, !host.isEmpty else { return nil }
            let tls = u.scheme == "wss"
            let port = u.port ?? (tls ? 443 : 80)
            var path = u.percentEncodedPath.isEmpty ? "/" : u.percentEncodedPath
            if let q = u.percentEncodedQuery { path += "?" + q }
            return RelayEndpoint(host: host, port: port, webSocket: true, tls: tls, path: path,
                                 authority: u.port.map { "\(host):\($0)" } ?? host)
        }
        guard let (h, p) = try? PairingLink.splitHostPort(s) else { return nil }
        return RelayEndpoint(host: h, port: p, webSocket: false, tls: false, path: "", authority: s)
    }
}

/// How a connection reaches the box: at its address, or through its relay.
enum DialRoute: Sendable, Hashable {
    case direct(host: String, port: Int)
    case relay(RelayEndpoint)

    var viaRelay: Bool { if case .relay = self { return true } else { return false } }
}

/// Completes once the TLS handshake finished (or fails with the first error). Passes everything through.
final class HandshakeWaiter: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = NIOAny
    private let promise: EventLoopPromise<String?>
    private var done = false

    init(promise: EventLoopPromise<String?>) { self.promise = promise }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case TLSUserEvent.handshakeCompleted(let proto) = event, !done {
            done = true
            promise.succeed(proto)
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if !done {
            done = true
            promise.fail(error)
        }
        context.fireErrorCaught(error)
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !done {
            done = true
            promise.fail(ChannelError.ioOnClosedChannel)
        }
        context.fireChannelInactive()
    }
}

/// The relay's side of a relayed connection, before TLS (pierd's package relay; docs/PROTOCOL.md §10): asks the relay
/// for the box by its key's fingerprint and waits for "OK", then passes every byte through untouched. The TLS that
/// follows is the box's own, pinned as on a direct connection: the relay only carries it.
final class RelayDialHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    static let version = "PIER-RELAY/1"

    private let fingerprint: String
    private let promise: EventLoopPromise<Void>
    private var pending: ByteBuffer?
    private var settled = false

    init(fingerprint: Fingerprint, promise: EventLoopPromise<Void>) {
        self.fingerprint = fingerprint.description
        self.promise = promise
    }

    private var asked = false

    /// On a WebSocket the channel is active long before: ask as soon as the handler is in.
    func handlerAdded(context: ChannelHandlerContext) {
        if context.channel.isActive { ask(context) }
    }

    func channelActive(context: ChannelHandlerContext) {
        ask(context)
        context.fireChannelActive()
    }

    private func ask(_ context: ChannelHandlerContext) {
        guard !asked else { return }
        asked = true
        var b = context.channel.allocator.buffer(capacity: 120)
        b.writeString("\(Self.version) DIAL \(fingerprint)\n")
        context.writeAndFlush(NIOAny(b), promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !settled else { context.fireChannelRead(data); return }
        var incoming = unwrapInboundIn(data)
        if pending == nil { pending = incoming } else { pending!.writeBuffer(&incoming) }
        guard let view = pending?.readableBytesView, let nl = view.firstIndex(of: UInt8(ascii: "\n")) else {
            if (pending?.readableBytes ?? 0) > 1024 { settle(.failure(PierError.protocolViolation("relay: answer too long"))) }
            return
        }
        let line = (pending!.readString(length: nl - view.startIndex) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        pending!.moveReaderIndex(forwardBy: 1)
        // Nothing may follow "OK" before TLS starts: the box waits for our hello.
        guard line == "OK", pending!.readableBytes == 0 else {
            settle(.failure(line == "OK" ? PierError.protocolViolation("relay: bytes before TLS") : Self.error(line)))
            return
        }
        pending = nil
        settle(.success(()))
    }

    func channelInactive(context: ChannelHandlerContext) {
        settle(.failure(PierError.transport("the relay closed the connection")))
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        settle(.failure(error))
        context.fireErrorCaught(error)
    }

    private func settle(_ result: Result<Void, Error>) {
        guard !settled else { return }
        settled = true
        promise.completeWith(result)
    }

    /// `ERR <code> [text]` as the person reads it.
    static func error(_ line: String) -> PierError {
        let code = line.hasPrefix("ERR ") ? String(line.dropFirst(4).split(separator: " ").first ?? "") : ""
        switch code {
        case "offline": return .transport("the box is not connected to its relay")
        case "timeout": return .transport("the box did not answer through its relay")
        case "busy": return .transport("the relay is busy; try again in a moment")
        default: return .protocolViolation("relay: \(line.prefix(80))")
        }
    }
}

/// A WebSocket's binary messages as one stream of bytes (the relay's protocol, then the box's TLS, travel inside):
/// frames in become bytes, bytes out become masked binary frames; pings are answered, a close closes.
final class WebSocketByteStream: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = WebSocketFrame
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = WebSocketFrame

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let frame = unwrapInboundIn(data)
        switch frame.opcode {
        case .binary, .continuation, .text:
            context.fireChannelRead(wrapInboundOut(frame.unmaskedData))
        case .ping:
            let pong = WebSocketFrame(fin: true, opcode: .pong, maskKey: .random(), data: frame.unmaskedData)
            context.writeAndFlush(wrapOutboundOut(pong), promise: nil)
        case .connectionClose:
            context.close(promise: nil)
        default:
            break
        }
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let bytes = unwrapOutboundIn(data)
        context.write(wrapOutboundOut(WebSocketFrame(fin: true, opcode: .binary, maskKey: .random(), data: bytes)), promise: promise)
    }
}

/// Sends the WebSocket's opening request once the channel is up (the upgrade handler adds its headers).
final class WebSocketOpener: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = NIOAny
    typealias OutboundOut = HTTPClientRequestPart
    let path: String
    let authority: String

    init(path: String, authority: String) {
        self.path = path
        self.authority = authority
    }

    func channelActive(context: ChannelHandlerContext) {
        var headers = HTTPHeaders()
        headers.add(name: "Host", value: authority)
        headers.add(name: "User-Agent", value: "Pier")
        headers.add(name: "Content-Length", value: "0")
        context.write(wrapOutboundOut(.head(HTTPRequestHead(version: .http1_1, method: .GET, uri: path, headers: headers))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        context.fireChannelActive()
    }
}

/// Fails the relay step on any error or close before the relay's OK (the WebSocket's TLS, its upgrade).
final class RelayGuard: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = NIOAny
    let promise: EventLoopPromise<Void>
    init(promise: EventLoopPromise<Void>) { self.promise = promise }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        promise.fail(error)
        context.fireErrorCaught(error)
    }

    func channelInactive(context: ChannelHandlerContext) {
        promise.fail(PierError.transport("the relay closed the connection"))
        context.fireChannelInactive()
    }
}

/// Dials the box, TLS 1.3, presents our Ed25519 client cert, and pins the server key by SPKI hash: at its address, or
/// through its relay, which is first asked for the box (`RelayDialHandler`; inside a WebSocket for a `ws(s)://` relay)
/// before the same TLS starts.
enum TLSDial {
    struct Result {
        let channel: Channel
        let negotiatedProtocol: String?
    }

    private static let boxTLSName = "pier-box-tls"

    /// The TLS to the box, by name: through a `wss://` relay the pipeline's first NIOSSLHandler is the front's.
    static func boxTLS(_ ops: ChannelPipeline.SynchronousOperations) throws -> NIOSSLHandler {
        guard let tls = try ops.context(name: boxTLSName).handler as? NIOSSLHandler else { throw PierError.tls("no TLS to the box") }
        return tls
    }

    static func connect(
        host: String,
        port: Int,
        identity: PierIdentity,
        pin: Fingerprint,
        alpn: [String],
        group: EventLoopGroup,
        timeout: TimeAmount = .seconds(15),
        configure: @escaping @Sendable (ChannelPipeline.SynchronousOperations) throws -> Void
    ) async throws -> Result {
        try await connect(route: .direct(host: host, port: port), identity: identity, pin: pin, alpn: alpn, group: group,
                          timeout: timeout, configure: configure)
    }

    static func connect(
        route: DialRoute,
        identity: PierIdentity,
        pin: Fingerprint,
        alpn: [String],
        group: EventLoopGroup,
        timeout: TimeAmount = .seconds(15),
        configure: @escaping @Sendable (ChannelPipeline.SynchronousOperations) throws -> Void
    ) async throws -> Result {
        let context = try sslContext(identity: identity, alpn: alpn)
        return try await dial(route: route, context: context, pin: pin, group: group, timeout: timeout, configure: configure)
    }

    /// The TLS a `wss://` relay's front speaks: the system's roots, the relay's name.
    private static let frontContext: NIOSSLContext? = {
        var config = TLSConfiguration.makeClientConfiguration()
        config.applicationProtocols = ["http/1.1"]
        return try? NIOSSLContext(configuration: config)
    }()

    /// The TLS context depends only on our identity and ALPN: built once (key parsing, BoringSSL setup), not per dial.
    private static let contexts = NIOLockedValueBox<[String: NIOSSLContext]>([:])

    private static func sslContext(identity: PierIdentity, alpn: [String]) throws -> NIOSSLContext {
        let key = "\(identity.fingerprint)|\(alpn.joined(separator: ","))"
        if let c = contexts.withLockedValue({ $0[key] }) { return c }
        var config = TLSConfiguration.makeClientConfiguration()
        config.minimumTLSVersion = .tlsv13
        config.maximumTLSVersion = .tlsv13
        // The default chain/hostname validation is replaced by the pin check below.
        config.certificateVerification = .noHostnameVerification
        config.applicationProtocols = alpn
        // BoringSSL does NOT advertise ed25519 in signature_algorithms by default; pierd only has an
        // Ed25519 certificate, so without this the server answers handshake_failure.
        config.verifySignatureAlgorithms = [.ed25519]
        let creds = try identity.tlsCredentials()
        config.certificateChain = creds.chain
        config.privateKey = creds.key
        let context: NIOSSLContext
        do { context = try NIOSSLContext(configuration: config) } catch { throw PierError.tls("\(error)") }
        contexts.withLockedValue { $0[key] = context }
        return context
    }

    private static func dial(
        route: DialRoute, context: NIOSSLContext, pin: Fingerprint, group: EventLoopGroup,
        timeout: TimeAmount, configure: @escaping @Sendable (ChannelPipeline.SynchronousOperations) throws -> Void
    ) async throws -> Result {

        let actualFP = NIOLockedValueBox<Fingerprint?>(nil)
        let handshake = group.next().makePromise(of: String?.self)
        let relayed = route.viaRelay ? group.next().makePromise(of: Void.self) : nil
        let (host, port): (String, Int)
        let relay: RelayEndpoint?
        switch route {
        case .direct(let h, let p): (host, port, relay) = (h, p, nil)
        case .relay(let r): (host, port, relay) = (r.host, r.port, r)
        }
        let front = relay?.tls == true ? frontContext : nil
        if relay?.tls == true && front == nil {
            handshake.fail(PierError.tls("no TLS for the relay"))
            relayed?.fail(PierError.tls("no TLS for the relay"))
            throw PierError.tls("could not set up TLS for the relay")
        }

        // TLS, pinned, then the caller's handlers: at once on a direct connection, after the relay's OK on a relayed one.
        @Sendable func addTLS(_ ops: ChannelPipeline.SynchronousOperations) throws {
            let ssl = try NIOSSLClientHandler(
                context: context,
                serverHostname: nil,
                customVerificationCallback: { certs, promise in
                    guard let leaf = certs.first,
                        let spki = try? leaf.extractPublicKey().toSPKIBytes()
                    else { return promise.succeed(.failed) }
                    let fp = Fingerprint(spki: spki)
                    if fp == pin {
                        promise.succeed(.certificateVerified)
                    } else {
                        actualFP.withLockedValue { $0 = fp }
                        promise.succeed(.failed)
                    }
                })
            try ops.addHandler(ssl, name: boxTLSName)
            try ops.addHandler(HandshakeWaiter(promise: handshake))
            try configure(ops)
        }

        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(timeout)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelOption(ChannelOptions.socketOption(.tcp_nodelay), value: 1)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let ops = channel.pipeline.syncOperations
                    switch (relay, relayed) {
                    case (let r?, let relayed?) where r.webSocket:
                        // The relay's protocol inside a WebSocket: its TLS (an HTTPS front) and upgrade first.
                        if let front { try ops.addHandler(try NIOSSLClientHandler(context: front, serverHostname: r.host)) }
                        let upgrader = NIOWebSocketClientUpgrader(maxFrameSize: 1 << 20) { channel, _ in
                            channel.eventLoop.makeCompletedFuture {
                                let ops = channel.pipeline.syncOperations
                                try ops.addHandler(WebSocketByteStream())
                                try ops.addHandler(RelayDialHandler(fingerprint: pin, promise: relayed))
                            }
                        }
                        try ops.addHTTPClientHandlers(withClientUpgrade: (upgraders: [upgrader], completionHandler: { _ in }))
                        try ops.addHandler(WebSocketOpener(path: r.path, authority: r.authority))
                        try ops.addHandler(RelayGuard(promise: relayed))
                    case (_, let relayed?):
                        try ops.addHandler(RelayDialHandler(fingerprint: pin, promise: relayed))
                    default:
                        try addTLS(ops)
                    }
                }
            }

        let channel: Channel
        do {
            channel = try await bootstrap.connect(host: host, port: port).get()
        } catch {
            relayed?.fail(error)
            handshake.fail(error)
            _ = try? await handshake.futureResult.get()
            throw map(error, pin: actualFP.withLockedValue { $0 }, expected: pin)
        }

        if let relayed {
            let wait = channel.eventLoop.scheduleTask(in: timeout) { relayed.fail(PierError.timeout) }
            do {
                try await relayed.futureResult.get()
                wait.cancel()
                try await channel.eventLoop.submit { try addTLS(channel.pipeline.syncOperations) }.get()
            } catch {
                wait.cancel()
                handshake.fail(error)
                try? await channel.close().get()
                throw map(error, pin: nil, expected: pin)
            }
        }

        let timer = channel.eventLoop.scheduleTask(in: timeout) { handshake.fail(PierError.timeout) }
        do {
            let proto = try await handshake.futureResult.get()
            timer.cancel()
            return Result(channel: channel, negotiatedProtocol: proto)
        } catch {
            timer.cancel()
            try? await channel.close().get()
            throw map(error, pin: actualFP.withLockedValue { $0 }, expected: pin)
        }
    }

    static func map(_ error: Error, pin actual: Fingerprint?, expected: Fingerprint) -> PierError {
        if let actual { return .pinMismatch(expected: expected.description, actual: actual.description) }
        if let e = error as? PierError { return e }
        if error is NIOSSLError || error is BoringSSLError { return .tls("\(error)") }
        if let e = error as? NIOConnectionError { return .transport("\(e)") }
        return .transport("\(error)")
    }
}
