//
//  File.swift
//  
//
//  Created by Darrell Root on 6/30/22.
//

import Foundation

public struct SnmpPdu: Equatable, CustomStringConvertible {
    public private(set) var pduType: SnmpPduType
    public private(set) var requestId: UInt32
    public private(set) var errorStatus: Int
    public private(set) var errorIndex: Int
    public private(set) var variableBindings: [VariableBinding]
    
    public var description: String {
        var result = "SNMP \(pduType) requestID: \(requestId) ErrorStatus: \(errorStatus)\n"
        for variableBinding in variableBindings {
            result += "  \(variableBinding)\n"
        }
        return result
    }
    
    init(data: Data) throws {
        try AsnValue.validateLength(data: data)
        guard data.count > 2 else {
            throw AsnError.badLength
        }
        //First octet has the pdu type
        switch data[data.startIndex] {
        case 0xa2:
            self.pduType = .getResponse
        default:
            throw AsnError.unsupportedType
        }
        
        var pduPosition = try AsnValue.prefixLength(data: data) + data.startIndex
        
        let requestIdValue = try AsnValue(data: data[(pduPosition)...])
        let requestIdLength = try AsnValue.pduLength(data: data[(pduPosition)...])
        guard case .integer(let requestId) = requestIdValue else {
            throw AsnError.unexpectedSnmpPdu
        }
        self.requestId = UInt32(requestId)
        pduPosition = pduPosition + requestIdLength
        
        let errorStatusValue = try AsnValue(data: data[(pduPosition)...])
        let errorStatusLength = try AsnValue.pduLength(data: data[(pduPosition)...])
        guard case .integer(let errorStatus) = errorStatusValue else {
            throw AsnError.unexpectedSnmpPdu
        }
        self.errorStatus = Int(errorStatus)
        pduPosition = pduPosition + errorStatusLength

        let errorIndexValue = try AsnValue(data: data[(pduPosition)...])
        let errorIndexLength = try AsnValue.pduLength(data: data[(pduPosition)...])
        guard case .integer(let errorIndex) = errorIndexValue else {
            throw AsnError.unexpectedSnmpPdu
        }
        self.errorIndex = Int(errorIndex)
        pduPosition = pduPosition + errorIndexLength
        
        // now at variable bindings header
        var remainingVariableBindingOctets = try AsnValue.pduLength(data: data[(data.startIndex + pduPosition)...])
        let variableBindingPrefix = try AsnValue.prefixLength(data: data[(data.startIndex + pduPosition)...])
        pduPosition += variableBindingPrefix
        remainingVariableBindingOctets -= variableBindingPrefix
        let variableBinding = try VariableBinding(data: data[(data.startIndex + pduPosition)...])
        self.variableBindings = [variableBinding]
        
        //TODO for now we assume one variable binding per SNMP message
        
    }
}
