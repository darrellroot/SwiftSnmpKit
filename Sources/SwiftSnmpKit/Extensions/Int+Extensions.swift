//
//  File.swift
//  
//
//  Created by Darrell Root on 7/1/22.
//

import Foundation

extension Array where Element == Int {
    /// Interprets an array of Int as a SNMP OID and returns its textual representation
    var oid: String {
        guard self.count > 0 else {
            return ""
        }
        var result = "\(self[0])"
        for position in 1..<self.count {
            result += ".\(self[position])"
        }
        return result
    }
}
extension Int {
    var bigEndianData: Data {
        // 4 bytes most significant first for AES initialization vector
        // only valid for positive integers
        var result = Data(count: 4)
        result[0] = UInt8((self & 0xff000000) >> 24)
        result[1] = UInt8((self & 0x00ff0000) >> 16)
        result[2] = UInt8((self & 0x0000ff00) >> 8)
        result[3] = UInt8(self & 0x000000ff)
        return result
    }
}
