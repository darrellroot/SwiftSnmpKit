//
//  File.swift
//  
//
//  Created by Darrell Root on 7/5/22.
//

import Foundation

/// Enumeration for the SNMP version.  The integer raw value is the integer encoded inside SNMP messages when transmitted.
public enum SnmpVersion: Int, AsnData {
    case v1 = 0
    case v2c = 1
    case v3 = 3
    
    internal var asn: AsnValue {
        return AsnValue.integer(Int64(self.rawValue))
    }
    internal var asnData: Data {
            return self.asn.asnData
    }
}
