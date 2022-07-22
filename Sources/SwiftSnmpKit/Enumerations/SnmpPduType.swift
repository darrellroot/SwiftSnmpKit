//
//  File.swift
//  
//
//  Created by Darrell Root on 7/1/22.
//

import Foundation
public enum SnmpPduType:  Equatable, CustomStringConvertible, AsnData {
    case getRequest
    case getNextRequest
    case getResponse
    case snmpReport
    
    public var description: String {
        switch self {
        case .getRequest:
            return "Get-Request"
        case .getNextRequest:
            return "Get-Next-Request"
        case .getResponse:
            return "Get-Response"
        case .snmpReport:
            return "SNMP-Report"
        }
    }
    /// This returns the ASN.1 prefix octet for the SNMP PDU Type, but the contents must be followed by the encoded length of the contents of the PDU.
    var asnData: Data {
        switch self {
        case .getRequest:
            return Data([0xa0])
        case .getNextRequest:
            return Data([0xa1])
        case .getResponse:
            return Data([0xa2])
        case .snmpReport:
            return Data([0xa8])
        }
    }
}
