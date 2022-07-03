//
//  File.swift
//  
//
//  Created by Darrell Root on 7/1/22.
//

import Foundation

/// Structure for the SNMP Protocol Data Unit
public struct SnmpMessage {
    public private(set) var version: Int
    public private(set) var community: String
    public private(set) var command: SnmpPduType
    public private(set) var requestId: Int
    public private(set) var errorStatus: Int
    public private(set) var errorIndex: Int
    public private(set) var variableBindings: [VariableBinding]
    
    init?(data: Data) {
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
        guard case .integer(let snmpVersion) = contents[0] else {
            AsnError.log("Expected AsnInteger, got \(contents[0])")
            return nil
        }
        self.version = Int(snmpVersion)
        
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
