import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL

/// Collects one HTTP/1.1 response (status + body).
final class HTTP1ResponseCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPClientResponsePart
    private let promise: EventLoopPromise<(Int, Data)>
    private var status = 0
    private var body = Data()
    private var done = false

    init(promise: EventLoopPromise<(Int, Data)>) { self.promise = promise }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let h): status = Int(h.status.code)
        case .body(let b):
            // `{"name":"…"}` or `{"error":"…"}`: anything bigger is not pierd.
            guard body.count + b.readableBytes <= H2Connection.maxErrorBytes else {
                if !done { done = true; promise.fail(PierError.protocolViolation("pairing answer too large")) }
                context.close(promise: nil)
                return
            }
            body.append(contentsOf: b.readableBytesView)
        case .end:
            if !done { done = true; promise.succeed((status, body)) }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if !done { done = true; promise.fail(error) }
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !done { done = true; promise.fail(ChannelError.ioOnClosedChannel) }
    }
}

public enum Pairing {
    static let exporterLabel = "EXPORTER-pier-pair-v1"

    /// Pairs with a box: TLS 1.3 + pin + ALPN http/1.1, `POST /v1/pair` with the exporter-bound proof.
    /// The identity must already be persisted (the code is consumed on the first accepted attempt).
    /// - Returns: the (not yet persisted) record. Use ``pair(link:clientName:identity:boxes:group:)`` to also persist it.
    public static func pair(
        link: BoxPairingLink,
        clientName: String,
        identity: PierIdentity,
        group: EventLoopGroup = NIOSingletons.posixEventLoopGroup
    ) async throws -> BoxRecord {
        // At the link's address; when it does not answer and the box has a relay, through the relay (pairing a phone
        // away from home). The proof below is bound to whichever TLS session carries it: the relay only passes it on.
        @Sendable func attempt(_ route: DialRoute, timeout: TimeAmount)
            async throws -> (TLSDial.Result, EventLoopPromise<(Int, Data)>)
        {
            let responsePromise = group.next().makePromise(of: (Int, Data).self)
            do {
                let dial = try await TLSDial.connect(
                    route: route, identity: identity, pin: link.fingerprint, alpn: ["http/1.1"], group: group, timeout: timeout
                ) { ops in
                    try ops.addHTTPClientHandlers()
                    try ops.addHandler(HTTP1ResponseCollector(promise: responsePromise))
                }
                return (dial, responsePromise)
            } catch {
                // No channel, so nothing completes the promise: fail it (NIO traps on a leaked promise in debug builds).
                responsePromise.fail(error)
                throw error
            }
        }
        let dial: TLSDial.Result
        let responsePromise: EventLoopPromise<(Int, Data)>
        let direct = DialRoute.direct(host: link.host, port: link.port)
        if let relay = link.relay.flatMap(RelayEndpoint.parse) {
            do {
                (dial, responsePromise) = try await attempt(direct, timeout: .seconds(4))
            } catch {
                (dial, responsePromise) = try await attempt(.relay(relay), timeout: .seconds(15))
            }
        } else {
            (dial, responsePromise) = try await attempt(direct, timeout: .seconds(15))
        }
        let channel = dial.channel
        defer { channel.close(promise: nil) }
        guard dial.negotiatedProtocol == "http/1.1" || dial.negotiatedProtocol == nil else {
            throw PierError.protocolViolation("unexpected ALPN \(dial.negotiatedProtocol ?? "-")")
        }

        let exporter = try await channel.eventLoop.submit {
            try TLSDial.boxTLS(channel.pipeline.syncOperations).exportKeyingMaterial(label: exporterLabel, length: 32)
        }.get()
        let proof = PierIdentity.pairingProof(code: link.code, exporter: exporter, clientFingerprint: identity.fingerprint)

        struct Body: Encodable { let name: String; let proof: String }
        let body = try JSONEncoder().encode(Body(name: clientName, proof: Data(proof).base64EncodedString()))
        var headers = HTTPHeaders()
        headers.add(name: "Host", value: link.address)
        headers.add(name: "Content-Type", value: "application/json")
        headers.add(name: "Content-Length", value: String(body.count))
        let head = HTTPRequestHead(version: .http1_1, method: .POST, uri: "/v1/pair", headers: headers)
        var buf = channel.allocator.buffer(capacity: body.count)
        buf.writeBytes(body)
        channel.write(HTTPClientRequestPart.head(head), promise: nil)
        channel.write(HTTPClientRequestPart.body(.byteBuffer(buf)), promise: nil)
        try await channel.writeAndFlush(HTTPClientRequestPart.end(nil)).get()

        let timer = channel.eventLoop.scheduleTask(in: .seconds(15)) { responsePromise.fail(PierError.timeout) }
        let status: Int
        let data: Data
        do {
            (status, data) = try await responsePromise.futureResult.get()
            timer.cancel()
        } catch {
            timer.cancel()
            throw (error as? PierError) ?? .transport("\(error)")
        }

        struct Reply: Decodable { let name: String?; let error: String? }
        let reply = try? JSONDecoder().decode(Reply.self, from: data)
        switch status {
        case 200:
            let boxName = PierName.fromHostname(reply?.name ?? "", fallback: "box")
            return BoxRecord(name: boxName, address: link.address, fingerprint: link.fingerprint, relay: link.relay)
        case 403: throw PierError.pairingRejected(reply?.error ?? "pairing rejected")
        case 429: throw PierError.rateLimited(message: reply?.error ?? "too many pairing attempts; try again in a minute")
        default: throw PierError.api(status: status, message: reply?.error ?? "pairing failed (HTTP \(status))", code: nil)
        }
    }

    /// Pair and persist the box (name collisions get a suffix; re-pairing the same key replaces its entry).
    public static func pair(
        link: BoxPairingLink,
        clientName: String,
        identity: PierIdentity,
        boxes: BoxStore,
        group: EventLoopGroup = NIOSingletons.posixEventLoopGroup
    ) async throws -> BoxRecord {
        let rec = try await pair(link: link, clientName: clientName, identity: identity, group: group)
        return try boxes.add(rec)
    }
}
