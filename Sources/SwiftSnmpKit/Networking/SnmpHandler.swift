//
//  File.swift
//  
//
//  Created by Darrell Root on 7/9/22.
//
import NIOCore

import Foundation

class SnmpHandler: ChannelInboundHandler {
    
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    weak var session: SnmpSession?
    
    deinit {
        print("deinitializing SnmpHandler")
    }
    init() {
    }
    public func channelActive(context: ChannelHandlerContext) {

        print("context \(context)")
        let snmpMessage = SnmpMessage(community: "public", command: .getNextRequest, oid: SnmpOid("1.3.6.1.2.1.1.1.0")!)
        let buffer = context.channel.allocator.buffer(bytes: snmpMessage.asnData)
        let remoteAddress = try! SocketAddress.makeAddressResolvingHost("129.168.4.120", port: 161)
        let envelope = AddressedEnvelope<ByteBuffer>(remoteAddress: remoteAddress, data: buffer)
        context.writeAndFlush(self.wrapOutboundOut(envelope),promise: nil)
        print("done with snmp handler")
    }
    public func channelInactive(context: ChannelHandlerContext) {
        //let channel = context.channel
        if let remoteAddress = context.remoteAddress {
            debugPrint("Channel from \(remoteAddress.description) disconnected")
        }
    }
    /*public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let id = ObjectIdentifier(context.channel)
        var read = self.unwrapInboundIn(data)
        logger.trace("\(#file) \(#function)")
    }*/
    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        debugPrint("Error: \(error)")
        if let remoteAddress = context.remoteAddress {
            debugPrint("Channel error from \(remoteAddress.description)")
        } else {
            debugPrint("Unable to disconnect player for context \(context)")
        }
        context.close(promise: nil)
    }
}
