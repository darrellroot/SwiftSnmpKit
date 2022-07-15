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
        SnmpError.log("initializing SnmpReceiver")
    }
    deinit {
        SnmpError.log("deinitializing SnmpReceiver")
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
        guard let snmpMessage = SnmpV2Message(data: Data(data)) else {
            SnmpError.log("Unable to decode snmp message from \(addressedEnvelope.remoteAddress) data: \(data.hexdump)")
            return
        }
        SnmpError.debug(snmpMessage.debugDescription)
        guard let snmpSender = SnmpSender.shared else {
            SnmpError.log("SnmpSender not initialized")
            return
        }
        snmpSender.received(message: snmpMessage)
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        SnmpError.log("error : \(error)")
        context.close(promise: nil)
    }
}
