//
//  File.swift
//  
//
//  Created by Darrell Root on 7/1/22.
//

import Foundation

/// Structure for the SNMP Protocol Data Unit
public struct SnmpMessage: AsnData {
    
    public private(set) var version: SnmpVersion
    public private(set) var community: String
    public private(set) var command: SnmpPduType
    public private(set) var requestId: Int32
    public private(set) var errorStatus: Int
    public private(set) var errorIndex: Int
    public private(set) var variableBindings: [VariableBinding]
    
    public var asnData: Data {
        let versionData = version.asnData
        let communityValue = AsnValue(octetString: community)
        let communityData = communityValue.asnData
        let pdu = SnmpPdu(type: command, variableBindings: variableBindings)
        let pduData = pdu.asnData
        let contentsData = versionData + communityData + pduData
        let lengthData = AsnValue.encodeLength(contentsData.count)
        let prefixData = Data([0x30])
        return prefixData + lengthData + contentsData
    }
    
    /// This initializer is used to create SNMP Messages for transmission
    /// - Parameters:
    ///   - version: SNMP version.  Default is v2c
    ///   - community: SNMP community
    ///   - command: SNMP command. Could be get or getNext.  Replies are not valid for this initializer.
    ///   - oid: The SNMP OID to be requested
    public init(version: SnmpVersion = .v2c, community: String, command: SnmpPduType, oid: SnmpOid) {
        self.version = version
        self.community = community
        self.command = command
        self.requestId = Int32.random(in: Int32.min...Int32.max)
        self.errorStatus = 0
        self.errorIndex = 0
        let variableBinding = VariableBinding(oid: oid)
        self.variableBindings = [variableBinding]
    }
    /// Creates SNMP message data structure from the data encapsulated inside a UDP SNMP reply.
    ///
    /// Takes data from a SNMP reply and uses it to create a SNMP message data structure.  Returns nil if the data cannot form a complete SNMP reply data structure.
    /// This initializer is not designed for creating a SNMP message for transmission.
    /// - Parameter data: The network contents of a UDP reply, with the IP and UDP headers already stripped off.
    public init?(data: Data) {
        guard let outerSequence = try? AsnValue(data: data) else {
            AsnError.log("Outer ASN is not a sequence")
            return nil
        }
        guard case .sequence(let contents) = outerSequence else {
            AsnError.log("Unable to extract AsnValues")
            return nil
        }
        guard contents.count == 3 else {
            AsnError.log("Expected 3 contents, found \(contents.count)")
            return nil
        }
        guard case .integer(let snmpVersionInteger) = contents[0] else {
            AsnError.log("Expected AsnInteger, got \(contents[0])")
            return nil
        }
        guard let snmpVersion = SnmpVersion(rawValue: Int(snmpVersionInteger)) else {
            AsnError.log("Received invalid SNMP Version \(snmpVersionInteger)")
            return nil
        }
        self.version = snmpVersion
        
        guard case .octetString(let communityData) = contents[1] else {
            AsnError.log("Expected community string, got \(contents[1])")
            return nil
        }
        let community = String(decoding: communityData, as: UTF8.self)
        guard community.count > 0 else {
            AsnError.log("Unable to decode community string from \(data)")
            return nil
        }
        self.community = community
        
        switch contents[2] {
        case .snmpResponse(let response):
            self.command = .getResponse
            self.requestId = response.requestId
            self.errorStatus = response.errorStatus
            self.errorIndex = response.errorIndex
            self.variableBindings = response.variableBindings
        default:
            AsnError.log("Expected SNMP response PDU, got \(contents[2])")
            return nil
        }
    }
}
