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
        //context.write(data, promise: nil)
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        context.flush()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("error :", error)
        context.close(promise: nil)
    }
}
