//
//  File.swift
//  
//
//  Created by Darrell Root on 7/9/22.
//

// check out https://stackoverflow.com/questions/58548813/swiftnio-send-and-receive-udp-broadcast
/*
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

        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.bootstrap = DatagramBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr),value: 1)
            .channelInitializer { channel in
                channel.pipeline
                    .addHandler(SnmpHandler())
            }
        // bind to blank host means any local ip
        // bind to blank port means pick a random local port
        // I think
        self.channel = try! bootstrap.bind(host: "192.168.4.23", port: 8988).wait()
        let remoteAddress = try! SocketAddress.makeAddressResolvingHost("192.168.4.120", port: 161)
        let snmpMessage = SnmpMessage(community: "public", command: .getNextRequest, oid: SnmpOid("1.3.6.1.2.1.1.1.0")!)
        print("sending message!")
    
        var buffer = channel.allocator.buffer(bytes: snmpMessage.asnData)
        print("buffer \(buffer)")
        let envelope = AddressedEnvelope(remoteAddress: remoteAddress, data: buffer)
        channel.writeAndFlush(envelope, promise: nil)
        try! channel.closeFuture.wait()
        print("client closed")


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
*/

