//
//  File.swift
//  
//
//  Created by Darrell Root on 7/12/22.
//

import Foundation
import NIOCore
import NIOPosix

public class SnmpSender: ChannelInboundHandler {
    public typealias InboundIn = AddressedEnvelope<ByteBuffer>
    
    static let snmpPort = 161
    /// This is a singleton for sending and receiving Snmp traffic
    /// It is automatically started up by any application that incorporates SnmpKit
    public static let shared: SnmpSender? = try? SnmpSender()
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel

    private var snmpRequests: [Int32:CheckedContinuation<String, Never>] = [:]
    
    private init() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.group = group
        let bootstrap = DatagramBootstrap(group: group).channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                debugPrint("adding handler")
                return channel.pipeline.addHandler(SnmpReceiver())
            }
        let channel = try bootstrap.bind(host: "0.0.0.0", port: 0).wait()
        /*bootstrap.channelInitializer { channel in
            channel.pipeline.addHandler(SnmpReceiver())
        }*/
        self.channel = channel
    }
    
    internal func received(message: SnmpMessage) {
        guard let continuation = snmpRequests[message.requestId] else {
            print("unable to find snmp request \(message.requestId)")
            return
        }
        var output = ""
        for variableBinding in message.variableBindings {
            output.append(variableBinding.description)
        }
        snmpRequests[message.requestId] = nil
        print("about to continue")
        continuation.resume(with: .success(output))
    }
    
    /// Sends a SNMPv2c Get request asynchronously and adds the requestID to the list of expected responses
    /// - Parameters:
    ///   - host: IPv4, IPv6, or hostname in String format
    ///   - community: SNMPv2c community in String format
    ///   - oid: SnmpOid to be requested
    /// - Returns: Result(SnmpVariableBinding or SnmpError)
    public func snmpGet(host: String, community: String, oid: SnmpOid) async throws -> String {
        let snmpMessage = SnmpMessage(community: community, command: .getRequest, oid: oid)
        guard let remoteAddress = try? SocketAddress(ipAddress: host, port: SnmpSender.snmpPort) else {
            throw SnmpError.invalidAddress
        }
        let data = snmpMessage.asnData
        let buffer = channel.allocator.buffer(bytes: data)
        let envelope = AddressedEnvelope(remoteAddress: remoteAddress, data: buffer)
        let _ = try await channel.writeAndFlush(envelope)
        return try await withCheckedContinuation { continuation in
            //snmpRequests[snmpMessage.requestId] = continuation.resume(with:)
            print("adding snmpRequests \(snmpMessage.requestId)")
            snmpRequests[snmpMessage.requestId] = continuation
        }

    }

    public func sendData(host: String, port: Int, data: Data) throws {
        guard let shared = SnmpSender.shared else {
            throw SnmpError.otherError
        }
        let buffer = channel.allocator.buffer(bytes: data)
        
        guard let remoteAddress = try? SocketAddress(ipAddress: host, port: port) else {
            throw SnmpError.otherError
        }
        let envelope = AddressedEnvelope(remoteAddress: remoteAddress, data: buffer)
        let result = channel.writeAndFlush(envelope)
        //try channel.closeFuture.wait()
    }
    deinit {
        debugPrint("Deinitializing SnmpSender Singleton")
        do {
            try self.group.syncShutdownGracefully()
        } catch {
            debugPrint("Unable to shutdown NIO gracefully: \(error.localizedDescription)")
        }
    }
}
