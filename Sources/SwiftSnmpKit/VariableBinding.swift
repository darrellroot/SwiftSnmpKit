//
//  File 2.swift
//  
//
//  Created by Darrell Root on 6/30/22.
//

import Foundation
public struct VariableBinding: Equatable, CustomStringConvertible {
    public private(set) var oid: SnmpOid
    public internal(set) var value: AsnValue // internal setter only used for test cases, treat as private
    
    /// This is used to create a varaible binding for a SNMP Request.  The value of the binding is automatically set to null.
    /// - Parameter oid: The OID to be requested
    init(oid: SnmpOid) {
        self.oid = oid
        self.value = AsnValue.null
    }
    
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
    internal var asnData: Data {
        let oidData = self.oid.asnData
        let valueData = self.value.asnData
        let lengthData = AsnValue.encodeLength(oidData.count + valueData.count)
        let prefix = Data([0x30])
        return prefix + lengthData + oidData + valueData
    }
}

// this extension intended only to support test cases
extension VariableBinding {
    internal mutating func setValue(_ value: AsnValue) {
        self.value = value
    }
}
