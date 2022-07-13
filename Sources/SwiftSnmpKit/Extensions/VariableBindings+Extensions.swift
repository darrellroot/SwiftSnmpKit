//
//  File.swift
//  
//
//  Created by Darrell Root on 7/8/22.
//

import Foundation

extension Array: AsnData where Element == SnmpVariableBinding {
    var asnData: Data {
        var variableBindingsData = Data()
        for variableBinding in self {
            let variableBindingData = variableBinding.asnData
            variableBindingsData += variableBindingData
        }
        let lengthData = AsnValue.encodeLength(variableBindingsData.count)
        let prefix = Data([0x30])
        return prefix + lengthData + variableBindingsData
    }
}
