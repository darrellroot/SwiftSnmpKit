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
    /// Must be greater than 0.  SNMPv3 send requests sometimes
    /// require 3 attempts, so the client-facing timeout may be 3 times
    /// this value
    public static var snmpTimeout: UInt64 = 5

    private var snmpRequests: [Int32:CheckedContinuation<Result<SnmpVariableBinding, Error>, Never>] = [:]
    
    /// Key is SNMP Agent hostname or IP in String format
    /// Value is SnmpEngineBoots Int as reported by SNMP agent
    /// These are gathered from SNMPv3 reports
    internal var snmpEngineBoots: [String:Int] = [:]
    /// Key is SNMP Agent hostname or IP in String format
    ///  Value is Date of most recent boot
    ///  These are gathered from SNMPv3 reports
    internal var snmpEngineBootDate: [String:Date] = [:]
    /// Maps SNMPv3 requestID/MessageID to hostname
    internal var snmpRequestToHost: [Int32:String] = [:]
    internal var snmpHostToEngineId: [String:String] = [:]
    
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
    internal func sent(message: SnmpV2Message, continuation: CheckedContinuation<Result<SnmpVariableBinding, Error>, Never>) {
        let requestId = message.requestId
        snmpRequests[requestId] = continuation
        Task.detached {
            SnmpError.debug("task detached starting")
            try? await Task.sleep(nanoseconds: SnmpSender.snmpTimeout * 1_000_000_000)
            SnmpError.debug("sleep complete")
            if let continuation = self.snmpRequests.removeValue(forKey: requestId) {
                continuation.resume(with: .success(.failure(SnmpError.noResponse)))
            }
            SnmpError.debug("continuation complete")
        }
        SnmpError.debug("sent complete")
    }
    
    internal func sent(message: SnmpV3Message, continuation: CheckedContinuation<Result<SnmpVariableBinding, Error>, Never>) {
        let requestId = message.messageId
        snmpRequests[requestId] = continuation
        Task.detached {
            SnmpError.debug("task detached starting")
            try? await Task.sleep(nanoseconds: SnmpSender.snmpTimeout * 1_000_000_000)
            SnmpError.debug("sleep complete")
            if let continuation = self.snmpRequests.removeValue(forKey: requestId) {
                continuation.resume(with: .success(.failure(SnmpError.noResponse)))
            }
            SnmpError.debug("continuation complete")
        }
        SnmpError.debug("sent complete")
    }
    
    internal func received(message: SnmpV2Message) {
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
    
    internal func received(message: SnmpV3Message) {
        guard let continuation = snmpRequests[message.messageId] else {
            SnmpError.log("unable to find snmp request \(message.messageId)")
            return
        }
        snmpRequests[message.messageId] = nil
        let snmpPdu = message.snmpPdu
        guard snmpPdu.errorStatus == 0 && snmpPdu.variableBindings.count > 0 else {
            SnmpError.debug("received SNMP error for request \(message.messageId)")
            continuation.resume(with: .success(.failure(SnmpError.snmpResponseError)))
            return
        }
        guard snmpPdu.pduType != .snmpReport else {
            guard let variableBinding = snmpPdu.variableBindings.first else {
                SnmpError.log("Unexpectedly received SNMPv3 report without a variable binding \(message)")
                continuation.resume(with: .success(.failure(SnmpError.snmpResponseError)))
                return
            }
            switch variableBinding.oid {
            case SnmpOid("1.3.6.1.6.3.15.1.1.1.0"):
                continuation.resume(with: .success(.failure(SnmpError.snmpUnknownSecurityLevel)))
            case SnmpOid("1.3.6.1.6.3.15.1.1.2.0"):
                let engineBoots = message.engineBoots
                let engineTime = message.engineTime
                let engineBootTime = Date(timeIntervalSinceNow: -Double(engineTime))
                if let agentHostname = self.snmpRequestToHost[message.messageId] {
                    self.snmpEngineBoots[agentHostname] = engineBoots
                    self.snmpEngineBootDate[agentHostname] = engineBootTime
                }
                continuation.resume(with: .success(.failure(SnmpError.snmpNotInTimeWindow)))
            case SnmpOid("1.3.6.1.6.3.15.1.1.3.0"):
                continuation.resume(with: .success(.failure(SnmpError.snmpUnknownUser)))
            case SnmpOid("1.3.6.1.6.3.15.1.1.4.0"):
                if let host = snmpRequestToHost[message.messageId] {
                    if !message.engineId.isEmpty {
                        snmpHostToEngineId[host] = message.engineId.hexString
                    }
                }
                continuation.resume(with: .success(.failure(SnmpError.snmpUnknownEngineId)))
            case SnmpOid("1.3.6.1.6.3.15.1.1.5.0"):
                continuation.resume(with: .success(.failure(SnmpError.snmpAuthenticationError)))
            case SnmpOid("1.3.6.1.6.3.15.1.1.6.0"):
                continuation.resume(with: .success(.failure(SnmpError.snmpDecryptionError)))
            default:
                SnmpError.log("Received SNMP repsonse with unexpected OID: \(message)")
                continuation.resume(with: .success(.failure(SnmpError.snmpResponseError)))
            }
            return
        }
        var output = ""
        for variableBinding in snmpPdu.variableBindings {
            output.append(variableBinding.description)
        }
        snmpRequests[message.messageId] = nil
        snmpRequestToHost[message.messageId] = nil
        SnmpError.debug("about to continue \(continuation)")
        continuation.resume(with: .success(.success(snmpPdu.variableBindings.first!)))
    }
    
    /// Sends a SNMPv2c Get request asynchronously and adds the requestID to the list of expected responses
    /// - Parameters:
    ///   - host: IPv4, IPv6, or hostname in String format
    ///   - command: A SnmpPduType.  At this time we only support .getRequest and .getNextRequest
    ///   - community: SNMPv2c community in String format
    ///   - oid: SnmpOid to be requested
    /// - Returns: Result(SnmpVariableBinding or SnmpError)
    public func send(host: String, command: SnmpPduType, community: String, oid: String) async -> Result<SnmpVariableBinding,Error> {
        guard let oid = SnmpOid(oid) else {
            return .failure(SnmpError.invalidOid)
        }
        // At this time we only support SNMP get and getNext
        guard command == .getRequest || command == .getNextRequest else {
            return .failure(SnmpError.unsupportedType)
        }
        let snmpMessage = SnmpV2Message(community: community, command: command, oid: oid)
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
            sent(message: snmpMessage, continuation: continuation)
            //snmpRequests[snmpMessage.requestId] = continuation
        }
    }
    
    /// Sends a SNMPv3 request asynchronously up to three times
    /// This allows SnmpSender to discover the engineID and timeout
    /// - Parameters:
    ///   - host: SNMP hostname, IPv4, or IPv6 address in string format
    ///   - tempUserName: SNMPv3 agent username
    ///   - pduType: SNMP PDU request type
    ///   - oid: SNMP OID in string format
    ///   - tempAuthenticationType: SNMPv3 authentication type
    ///   - tempPassword: SNMPv3 password if needed, or nil
    /// - Returns: Result(SnmpVariableBinding or SnmpError)
    public func send(host: String, userName: String, pduType: SnmpPduType, oid: String, authenticationType: SnmpV3Authentication = .noAuth, authPassword: String? = nil, privPassword: String? = nil) async -> Result<SnmpVariableBinding,Error> {
        guard pduType == .getRequest || pduType == .getNextRequest else {
            return .failure(SnmpError.unsupportedType)
        }
        guard let oid = SnmpOid(oid) else {
            return .failure(SnmpError.invalidOid)
        }
        // attempt #1 (may get engineId)
        let result1 = await self.sendV3(host: host, userName: userName, pduType: pduType, oid: oid, authenticationType: authenticationType, authPassword: authPassword, privPassword: privPassword)
        guard case let .failure(_) = result1 else {
            return result1
        }
        // attempt #2 (may update time interval)
        let result2 = await self.sendV3(host: host, userName: userName, pduType: pduType, oid: oid, authenticationType: authenticationType, authPassword: authPassword, privPassword: privPassword)
        guard case let .failure(_) = result2 else {
            return result2
        }
        // attempt #3 (last chance!)
        let result3 = await self.sendV3(host: host, userName: userName, pduType: pduType, oid: oid, authenticationType: authenticationType, authPassword: authPassword, privPassword: privPassword)
        return result3
    }
    
    /// Sends a SNMPv3 Get request asynchronously ONCE and adds the requestID to the list of expected responses
    /// - Parameters:
    ///   - host: IPv4, IPv6, or hostname in String format
    ///   - command: A SnmpPduType.  At this time we only support .getRequest and .getNextRequest
    ///   - community: SNMPv2c community in String format
    ///   - oid: SnmpOid to be requested
    ///   - privacyPassword: Setting this turns on AES encryption
    /// - Returns: Result(SnmpVariableBinding or SnmpError)
    internal func sendV3(host: String, userName tempUserName: String, pduType: SnmpPduType, oid: SnmpOid, authenticationType tempAuthenticationType: SnmpV3Authentication = .noAuth, authPassword tempAuthPassword: String? = nil, privPassword tempPrivPassword: String? = nil) async -> Result<SnmpVariableBinding,Error> {
        // At this time we only support SNMP get and getNext
        guard pduType == .getRequest || pduType == .getNextRequest else {
            return .failure(SnmpError.unsupportedType)
        }
        let variableBinding = SnmpVariableBinding(oid: oid)
        let authenticationType: SnmpV3Authentication
        // send blank engineId if we don't know engineId
        var engineId: String
        var userName: String
        // If we don't know the engine-id or engine-time
        // we need to send unauthenticated snmp messages
        // with these passwords set to nil
        // so we don't directly use the function parameters
        var authPassword: String?
        var privPassword: String?
        if let possibleEngineId = snmpHostToEngineId[host] {
            engineId = possibleEngineId
            authenticationType = tempAuthenticationType
            userName = tempUserName
            authPassword = tempAuthPassword
            privPassword = tempPrivPassword
        } else {
            // trying to trigger a report rather than actually getting our data
            engineId = ""
            authenticationType = .noAuth
            userName = ""
            authPassword = nil
            privPassword = nil
        }
        guard let remoteAddress = try? SocketAddress(ipAddress: host, port: SnmpSender.snmpPort) else {
            return .failure(SnmpError.invalidAddress)
        }
        let engineBoots = snmpEngineBoots[host] ?? 0
        let bootDate = snmpEngineBootDate[host] ?? Date()
        let dateInterval = DateInterval(start: bootDate, end: Date())
        let engineTime = Int(dateInterval.duration)
        
        guard var snmpMessage = SnmpV3Message(engineId: engineId, userName: userName, type: pduType, variableBindings: [variableBinding], authenticationType: authenticationType, authPassword: authPassword, privPassword: privPassword, engineBoots: engineBoots, engineTime: engineTime) else {
            return .failure(SnmpError.unexpectedSnmpPdu)
        }

        let data = snmpMessage.asnData
        let buffer = channel.allocator.buffer(bytes: data)
        let envelope = AddressedEnvelope(remoteAddress: remoteAddress, data: buffer)
        do {
            let _ = try await channel.writeAndFlush(envelope)
            self.snmpRequestToHost[snmpMessage.messageId] = host
        } catch (let error) {
            return .failure(error)
        }
        return await withCheckedContinuation { continuation in
            SnmpError.debug("adding snmpRequests \(snmpMessage.messageId)")
            sent(message: snmpMessage, continuation: continuation)
        }
    }

    internal func sendData(host: String, port: Int, data: Data) throws {
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
