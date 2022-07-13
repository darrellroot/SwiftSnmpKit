//
//  File.swift
//  
//
//  Created by Darrell Root on 7/9/22.
//
import NIOCore

import Foundation

class SnmpHandler : ChannelInboundHandler {
    // typealias changes to wrap out ByteBuffer in an AddressedEvelope which describes where the packages are going
    // inbound handler
    public typealias InboundIn = AddressedEnvelope<ByteBuffer>
    public typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    // outbound handler
    //public typealias OutboundIn = AddressedEnvelope<ByteBuffer>

    public init() {
    }
    
    /*//outboundhandler method
    // The method just grabs the data on the way out and adds the expected input handler
    public func write(ctx: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let expectedNumBytes = self.unwrapOutboundIn(data).data.readableBytes
        ctx.channel.pipeline.add(handler: SnmpHandler(expectedNumBytes)).whenComplete {
            ctx.write(data, promise: promise)
        }
    }*/
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        
        print("Received data back from the agent, closing channel")
        context.close(promise: nil)
    }
    
    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        print("error: ", error)
        context.close(promise: nil)
    }
}
