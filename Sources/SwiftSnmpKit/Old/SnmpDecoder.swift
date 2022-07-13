//
//  File.swift
//  
//
//  Created by Darrell Root on 7/11/22.
//
/*
import Foundation
import NIOCore

class SnmpDecoder: ByteToMessageDecoder {
    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer

    public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        debugPrint("Readable Bytes \(buffer.readableBytes)")
        guard buffer.readableBytes > 0 else {
            return .needMoreData
        }
        guard let bytes = buffer.readBytes(length: buffer.readableBytes) else {
            debugPrint("Unable to read bytes")
            return .needMoreData
        }
        guard let snmpMessage = SnmpMessage(data: Data(bytes)) else {
            debugPrint("Unable to decode snmp message")
            return .needMoreData
        }
        print(snmpMessage)
        return .needMoreData
    }
}
 */
