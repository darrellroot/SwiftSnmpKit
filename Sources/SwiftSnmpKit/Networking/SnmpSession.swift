//
//  File.swift
//  
//
//  Created by Darrell Root on 7/9/22.
//

import Foundation
import NIOCore
import NIOPosix

@available(macOS 10.15.0, *)
public class SnmpSession {
    let version: SnmpVersion
    let community: String
    let group: MultiThreadedEventLoopGroup
    let channel: Channel
    let bootstrap: DatagramBootstrap
    var context: ChannelHandlerContext?
    
    deinit {
        debugPrint("Deinitializing SnmpSession")
        try? self.group.syncShutdownGracefully()
    }
    public init?(host: String, version: SnmpVersion, community: String) {
        self.version = version
        self.community = community
        // just testing if we can resolve the remote host
        #warning("remove unneeded blocking socketaddress call")
        /*guard let remoteAddress = try? SocketAddress.makeAddressResolvingHost(host, port: 2593) else {
            AsnError.log("Failed to resolve host \(host)")
            return nil
        }*/
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.bootstrap = DatagramBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr),value: 1)
            .channelInitializer { channel in
                channel.pipeline
                    .addHandler(SnmpHandler())
                    .flatMap { v in
                        channel.pipeline.addHandler(ByteToMessageHandler(SnmpDecoder()))
                    }
            }
        // bind to blank host means any local ip
        // bind to blank port means pick a random local port
        // I think
        let futureChannel = bootstrap.bind(host: "", port: 0)
        do {
            let channel = try futureChannel.wait()
            self.channel = channel
        } catch {
            print(error.localizedDescription)
            return nil
        }
        /*guard let channel = try? { () -> Channel in
            return try bootstrap.bind(host: "example.com", port: 2593).wait()
        }() else {
            return nil
        }*/
        do {
            try channel.closeFuture.wait()
        } catch {
            debugPrint("channel close future error \(error.localizedDescription)")
        }
        print("succeeded with channel initialization")
    }
    public func sendData(host: String, data: Data) throws {
        guard let remoteAddress = try? SocketAddress(ipAddress: host, port: 161) else {
            debugPrint("\(#file) \(#function) Error: unable to resolve ip \(host)")
            return
        }
        let buffer = channel.allocator.buffer(bytes: data)
        let envelope = AddressedEnvelope<ByteBuffer>(remoteAddress: remoteAddress, data: buffer)
        
        let result = channel.writeAndFlush(envelope)
    }
}


