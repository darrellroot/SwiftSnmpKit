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
        print("initializing SnmpReceiver")
    }
    deinit {
        print("deinitializing SnmpReceiver")
    }
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let addressedEnvelope = self.unwrapInboundIn(data)
        print("Recieved data from \(addressedEnvelope.remoteAddress)")
        var buffer = addressedEnvelope.data
        let readableBytes = buffer.readableBytes
        guard let data = buffer.readBytes(length: buffer.readableBytes) else {
            debugPrint("unexpectedly unable to read \(readableBytes) bytes from \(addressedEnvelope.remoteAddress)")
            return
        }
        guard let snmpMessage = SnmpMessage(data: Data(data)) else {
            debugPrint("Unable to decode snmp message from \(data.hexdump)")
            return
        }
        print(snmpMessage)
        
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("error :", error)
        context.close(promise: nil)
    }
}
