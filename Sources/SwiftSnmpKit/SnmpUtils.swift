//
//  File.swift
//  
//
//  Created by Darrell Root on 7/6/22.
//

import Foundation

struct SnmpUtils {
    internal static func powerOf128(_ power: Int) -> Int {
        var result = 1
        for _ in 0..<power {
            result = result * 128
        }
        return result
    }
    internal static func powerOf256(_ power: Int) -> Int {
        var result = 1
        for _ in 0..<power {
            result = result * 256
        }
        return result
    }
}
