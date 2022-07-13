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
    
    /// Set this to true to print verbose debugging messages
    /// See SnmpError.debug()
    public static let debug = false
    /// Global timeout for SnmpRequests in seconds
    /// Must be greater than 0
    public static let snmpTimeout: UInt32 = 10

    private var snmpRequests: [Int32:CheckedContinuation<Result<SnmpVariableBinding, Error>, Never>] = [:]
    
    private init() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.group = group
        let bootstrap = DatagramBootstrap(group: group).channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                SnmpError.debug("adding handler")
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
            SnmpError.log("unable to find snmp request \(message.requestId)")
            return
        }
        guard message.errorStatus == 0 && message.variableBindings.count > 0 else {
            snmpRequests[message.requestId] = nil
            SnmpError.debug("received SNMP error for request \(message.requestId)")
            continuation.resume(with: .success(.failure(SnmpError.snmpResponseError)))
            return
        }
        var output = ""
        for variableBinding in message.variableBindings {
            output.append(variableBinding.description)
        }
        snmpRequests[message.requestId] = nil
        SnmpError.debug("about to continue \(continuation)")
                                continuation.resume(with: .success(.success(message.variableBindings.first!)))
    }
    
    /// Sends a SNMPv2c Get request asynchronously and adds the requestID to the list of expected responses
    /// - Parameters:
    ///   - host: IPv4, IPv6, or hostname in String format
    ///   - community: SNMPv2c community in String format
    ///   - oid: SnmpOid to be requested
    /// - Returns: Result(SnmpVariableBinding or SnmpError)
    public func snmpGet(host: String, community: String, oid: SnmpOid) async -> Result<SnmpVariableBinding,Error> {
        let snmpMessage = SnmpMessage(community: community, command: .getRequest, oid: oid)
        guard let remoteAddress = try? SocketAddress(ipAddress: host, port: SnmpSender.snmpPort) else {
            return .failure(SnmpError.invalidAddress)
        }
        let data = snmpMessage.asnData
        let buffer = channel.allocator.buffer(bytes: data)
        let envelope = AddressedEnvelope(remoteAddress: remoteAddress, data: buffer)
        do {
            let _ = try await channel.writeAndFlush(envelope)
        } catch (let error) {
            return .failure(error)
        }

        return await withCheckedContinuation { continuation in
            //snmpRequests[snmpMessage.requestId] = continuation.resume(with:)
            
            SnmpError.debug("adding snmpRequests \(snmpMessage.requestId)")
            snmpRequests[snmpMessage.requestId] = continuation
            sleep(SnmpSender.snmpTimeout)
            if let gotContinuation = snmpRequests.removeValue(forKey: snmpMessage.requestId) {
                print("snmp timed out, triggering continuation")
                gotContinuation.resume(with: .success(.failure(SnmpError.noResponse)))
            }
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
        SnmpError.log("Deinitializing SnmpSender Singleton")
        do {
            try self.group.syncShutdownGracefully()
        } catch {
            SnmpError.log("Unable to shutdown NIO gracefully: \(error.localizedDescription)")
        }
    }
}
