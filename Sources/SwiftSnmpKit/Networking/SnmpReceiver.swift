//
//  File.swift
//  
//
//  Created by Darrell Root on 7/12/22.
//

import Foundation
import NIOCore
import NIOPosix

class SnmpReceiver: ChannelInboundHandler {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    
    init() {
        SnmpError.debug("initializing SnmpReceiver")
    }
    deinit {
        SnmpError.debug("deinitializing SnmpReceiver")
    }
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let addressedEnvelope = self.unwrapInboundIn(data)
        SnmpError.debug("Recieved data from \(addressedEnvelope.remoteAddress)")
        var buffer = addressedEnvelope.data
        let readableBytes = buffer.readableBytes
        guard let data = buffer.readBytes(length: buffer.readableBytes) else {
            SnmpError.log("unexpectedly unable to read \(readableBytes) bytes from \(addressedEnvelope.remoteAddress)")
            return
        }
        guard let snmpSender = SnmpSender.shared else {
            SnmpError.log("SnmpSender not initialized")
            return
        }
        if let snmpMessage = SnmpV2Message(data: Data(data)) {
            SnmpError.debug(snmpMessage.debugDescription)
            snmpSender.received(message: snmpMessage)
        } else if let snmpMessage = SnmpV3Message(data: Data(data)) {
            SnmpError.debug(snmpMessage.debugDescription)
            snmpSender.received(message: snmpMessage)
        } else {
            SnmpError.log("Unable to decode snmp message from \(addressedEnvelope.remoteAddress) data: \(data.hexdump)")
            return
        }
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        SnmpError.log("error : \(error)")
        context.close(promise: nil)
    }
}
