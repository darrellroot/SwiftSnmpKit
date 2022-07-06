//
//  File.swift
//  
//
//  Created by Darrell Root on 7/5/22.
//

import Foundation
import CoreText

/// Enumeration for the SNMP version.  The integer raw value is the integer encoded inside SNMP messages when transmitted.
public enum SnmpVersion: Int {
    case v1 = 0
    case v2c = 1
    case v3 = 2
}
