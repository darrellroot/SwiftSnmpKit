//
//  File.swift
//  
//
//  Created by Darrell Root on 7/15/22.
//

import Foundation

extension String {
    internal var hexstream: Data? {
        var total = 0
        var data = Data(capacity: (self.count / 2 + 1))
        for (count,char) in self.enumerated() {
            guard let charValue = Int(String(char), radix: 16) else {
                SnmpError.log("makeData: invalid char \(char) at position \(count)")
                return nil
            }
            if count % 2 == 0 {
                total = charValue * 16
            } else {
                total = total + charValue
                data.append(UInt8(total))
            }
        }
        return data
    }
}
