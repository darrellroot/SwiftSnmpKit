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
    
    static let shared: SnmpSender? = try? SnmpSender()
    let group: MultiThreadedEventLoopGroup
    let channel: Channel

    
    private init() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.group = group
        let bootstrap = DatagramBootstrap(group: group).channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                debugPrint("adding handler")
                return channel.pipeline.addHandler(SnmpReceiver())
            }
        let channel = try bootstrap.bind(host: "0.0.0.0", port: 0).wait()
        /*bootstrap.channelInitializer { channel in
            channel.pipeline.addHandler(SnmpReceiver())
        }*/
        self.channel = channel
    }

    public func sendData(host: String, port: Int, data: Data) throws {
        guard let shared = SnmpSender.shared else {
            throw AsnError.otherError
        }
        let buffer = channel.allocator.buffer(bytes: data)
        
        guard let remoteAddress = try? SocketAddress(ipAddress: host, port: port) else {
            throw AsnError.otherError
        }
        let envelope = AddressedEnvelope(remoteAddress: remoteAddress, data: buffer)
        let result = channel.writeAndFlush(envelope)
        //try channel.closeFuture.wait()
    }
    deinit {
        debugPrint("Deinitializing SnmpSender Singleton")
        do {
            try self.group.syncShutdownGracefully()
        } catch {
            debugPrint("Unable to shutdown NIO gracefully: \(error.localizedDescription)")
        }
    }
}
