//
//  AsnError.swift
//  Snmp1
//
//  Created by Darrell Root on 6/29/22.
//

import Foundation
public enum AsnError: Error {
    case badLength
    case unsupportedType
    case otherError
    case unexpectedSnmpPdu
    
    static func log(_ message: String,
            function: String = #function,
                file: String = #file,
                line: Int = #line) {
        #if DEBUG
            print("Error: \(file):\(function) line \(line): \(message)")
        #endif
    }
}
