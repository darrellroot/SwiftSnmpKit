//
//  File.swift
//  
//
//  Created by Darrell Root on 7/1/22.
//

import Foundation
public enum SnmpPduType: Int, Equatable, CustomStringConvertible, AsnData {
    case getNextRequest = 1
    case getResponse = 2
    
    public var description: String {
        switch self {
        case .getNextRequest:
            return "Get-Next-Request"
        case .getResponse:
            return "Get-Response"
        }
    }
    /// This returns the ASN.1 prefix octet for the SNMP PDU Type, but the contents must be followed by the encoded length of the contents of the PDU.
    var asnData: Data {
        switch self {
            
        case .getNextRequest:
            return Data([0xa1])
        case .getResponse:
            return Data([0xa2])
        }
    }
}
