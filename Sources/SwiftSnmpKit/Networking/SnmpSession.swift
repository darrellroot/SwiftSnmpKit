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
    deinit {
        try? self.group.syncShutdownGracefully()
    }
    public init?(host: String, version: SnmpVersion, community: String) async {
        self.version = version
        self.community = community
        // just testing if we can resolve the remote host
        #warning("remove unneeded blocking socketaddress call")
        guard let remoteAddress = try? SocketAddress.makeAddressResolvingHost(host, port: 161) else {
            AsnError.log("Failed to resolve host \(host)")
            return nil
        }
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        
        let bootstrap = DatagramBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr),value: 1)
            .channelInitializer { channel in
                channel.pipeline.addHandler(SnmpHandler())
            }
        let futureChannel = bootstrap.bind(to: remoteAddress)
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
        print("succeeded with channel initialization")
    }
}
