//
//  File.swift
//  
//
//  Created by Darrell Root on 7/5/22.
//

import Foundation

public struct SnmpOid: CustomStringConvertible, Equatable {
    private(set) var nodes: [Int] // must not be empty
    
    /// Initializes a SNMP OID from a non-empty array of non-negative integers
    ///
    /// This does not perform any validation that the SNMP OID exists in a MIB.
    /// - Parameter nodes: The nodes of the OID in order as an array of integers.  Each node must be non-negative.  There must be at least one node.
    public init?(nodes: [Int]) {
        guard nodes.count > 0 else {
            return nil
        }
        for node in nodes {
            guard node >= 0 else {
                return nil
            }
        }
        self.nodes = nodes
    }
    
    /// Initializes a SNMP OID from a String
    ///
    ///
    /// - Parameter nodes: A String of the form "1.3.6.1.4".  Each node must be non-negative.  There must be at least one node.
    public init?(_ nodeString: String) {
        var nodeStrings = nodeString.components(separatedBy: ".")
        var nodes: [Int] = []
        for thisNodeString in nodeStrings {
            guard let thisNodeInt = Int(thisNodeString) else {
                return nil
            }
            guard thisNodeInt >= 0 else {
                return nil
            }
            nodes.append(thisNodeInt)
        }
        guard nodes.count > 0 else {
            return nil
        }
        self.nodes = nodes
        return
    }
    public var description: String {
        guard nodes.count > 0 else {
            // should not get here, but I'm not ready to crash
            AsnError.log("Warning: SNMP OID node count is unexpectely \(nodes.count)")
            return "."
        }
        var result = "\(nodes[0])"
        for nodeIndex in 1..<nodes.count {
            result += ".\(nodes[nodeIndex])"
        }
        return result
    }
    
}
