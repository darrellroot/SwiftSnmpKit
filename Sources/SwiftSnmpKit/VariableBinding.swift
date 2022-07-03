//
//  File 2.swift
//  
//
//  Created by Darrell Root on 6/30/22.
//

import Foundation
public struct VariableBinding: Equatable, CustomStringConvertible {
    public private(set) var oid: [Int]
    public private(set) var value: AsnValue
    
    init(data: Data) throws {
        let objectName = try AsnValue(data: data)
        let nameLength = try AsnValue.pduLength(data: data)
        guard case .sequence(let sequence) = objectName else {
            AsnError.log("Expected Sequence got \(objectName)")
            throw AsnError.unexpectedSnmpPdu
        }
        guard sequence.count == 2 else {
            AsnError.log("Expected sequence containing two values got \(sequence)")
            throw AsnError.unexpectedSnmpPdu
        }
        let oidValue = sequence[0]
        guard case .oid(let oid) = oidValue else {
            AsnError.log("Expected OID got \(oidValue)")
            throw AsnError.unexpectedSnmpPdu
        }
        self.oid = oid
        let value = sequence[1]
        //let value = try AsnValue(data: data[(data.startIndex+nameLength)...])
        self.value = value
    }
    public var description: String {
        return "VariableBinding: \(oid): \(value)"
    }
}
