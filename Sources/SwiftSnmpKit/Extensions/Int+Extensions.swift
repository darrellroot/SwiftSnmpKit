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
