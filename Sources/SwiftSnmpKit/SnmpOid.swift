//
//  File.swift
//  
//
//  Created by Darrell Root on 7/5/22.
//

import Foundation

/// This structure represents a SNMP OID.  SwiftSnmpKit uses this
/// internally, but you can test whether your OID string is valid by
/// attempting to initialize a SnmpOid.
/// SwiftSnmpKit does not check MIB files to see if OIDs exist.
public struct SnmpOid: CustomStringConvertible, Equatable, AsnData {
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
    
    /// Initializes a SNMP OID from a String of the form "1.3.6.1.4"
    /// - Parameter nodeString: A String of the form ".1.3.6.1.4" or "1.3.6.1.4".  Each node must be non-negative.  There must be at least two nodes.
    public init?(_ nodeString: String) {
        var nodeStrings = nodeString.components(separatedBy: ".")
        var nodes: [Int] = []
        // SNMP OIDs must have at least 2 nodes
        guard nodeStrings.count > 1 else {
            return nil
        }
        // if oid leads with ., remove the nonexistent entry
        if nodeStrings[0] == "" {
            nodeStrings.remove(at:0)
        }
        // SNMP OIDs still must have at least 2 nodes
        guard nodeStrings.count > 1 else {
            return nil
        }
        for thisNodeString in nodeStrings {
            guard let thisNodeInt = Int(thisNodeString) else {
                return nil
            }
            guard thisNodeInt >= 0 else {
                return nil
            }
            nodes.append(thisNodeInt)
        }
        self.nodes = nodes
        return
    }
    /// Displays the OID in String format as integers separated by a .
    public var description: String {
        guard nodes.count > 0 else {
            // should not get here, but I'm not ready to crash
            SnmpError.log("Warning: SNMP OID node count is unexpectely \(nodes.count)")
            return "."
        }
        var result = "\(nodes[0])"
        for nodeIndex in 1..<nodes.count {
            result += ".\(nodes[nodeIndex])"
        }
        return result
    }
    
    internal var asn: AsnValue {
        return AsnValue.oid(self)
    }

    /// Encodes an OID into a ASN.1 Data array
    /// - Parameter oid: SNMP OID as an array of integers
    /// - Returns: ASN.1 data encoding for the OID
    internal var asnData: Data {
        guard nodes.count > 1 else {
            SnmpError.log("OID's must have at least two elements")
            fatalError()
        }
        var data = Data()
        data.append(UInt8(40 * nodes[0] + nodes[1]))
        for node in nodes[2...] {
            data.append(AsnValue.base128ToData(node))
        }
        let oidLength = AsnValue.encodeLength(data.count)
        data.insert(contentsOf: oidLength, at: 0)
        data.insert(6, at: 0)
        return data
    }
}
