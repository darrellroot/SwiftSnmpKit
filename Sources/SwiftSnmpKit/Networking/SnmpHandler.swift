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
    
    public func channelActive(context: ChannelHandlerContext) {
        if let remoteAddress = context.remoteAddress {
        //let channel = context.channel
            debugPrint("New channel from \(remoteAddress)")
        } else {
            debugPrint("New channel but context is nil")
        }
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
