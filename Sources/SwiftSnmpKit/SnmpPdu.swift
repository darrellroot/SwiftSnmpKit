//
//  File.swift
//  
//
//  Created by Darrell Root on 6/30/22.
//

import Foundation

/// SnmpPdu represents the PDU portion of a SNMP request
/// Most notably the variable bindings which include the OIDs to
/// request and the resulting values.
public struct SnmpPdu: Equatable, CustomStringConvertible, AsnData {
    /// Type of the SNMP PDU
    public private(set) var pduType: SnmpPduType
    // internal set only for testing
    /// SNMP requestId.
    public internal(set) var requestId: Int32
    /// The integer in the SNMP reply indicating if an error occured.
    public private(set) var errorStatus: Int
    /// The integer in the SNMP reply indicating the location of the error
    public private(set) var errorIndex: Int
    /// An array of variable bindings.  Each variable binding includes
    /// the OID and the corresponding value encoded in ASN syntax.
    /// As of 2022, SwiftSnmpKit does not interpret the value based on any MIB file.
    public private(set) var variableBindings: [SnmpVariableBinding]
    
    private var requestIdAsn: AsnValue {
        return AsnValue.integer(Int64(requestId))
    }
    private var errorStatusAsn: AsnValue {
        return AsnValue.integer(Int64(errorStatus))
    }
    private var errorIndexAsn: AsnValue {
        return AsnValue.integer(Int64(errorIndex))
    }
    
    /// This will output the SNMP PDU as a hierarchical structure of ASN values.
    internal var asn: AsnValue {
        switch self.pduType {
            
        case .getRequest:
            return AsnValue.snmpGet(self)
        case .getNextRequest:
            return AsnValue.snmpGetNext(self)
        case .getResponse:
            return AsnValue.snmpResponse(self)
        case .snmpReport:
            return AsnValue.snmpReport(self)
        }
    }
    /// This will output the SNMP PDU as data ready for transmission.
    internal var asnData: Data {
        let requestInteger = AsnValue.integer(Int64(requestId))
        let requestData = requestInteger.asnData
        let errorStatusInteger = AsnValue.integer(Int64(errorStatus))
        let errorStatusData = errorStatusInteger.asnData
        let errorIndexInteger = AsnValue.integer(Int64(errorIndex))
        let errorIndexData = errorIndexInteger.asnData
        let variableBindingsData = variableBindings.asnData
        let contentsData = requestData + errorStatusData + errorIndexData + variableBindingsData
        let lengthData = AsnValue.encodeLength(contentsData.count)
        return pduType.asnData + lengthData + contentsData
    }
    /// Creates a SNMP PDU
    /// - Parameters:
    ///   - type: Type of SNMP PDU to create
    ///   - requestId: Int32 specifying the requestID
    ///   - variableBindings: Variable bindings to transmit.  For requests the values are often null.
    init(type: SnmpPduType, requestId: Int32, variableBindings: [SnmpVariableBinding]) {
        self.pduType = type
        self.requestId = requestId
        self.errorStatus = 0
        self.errorIndex = 0
        self.variableBindings = variableBindings
    }
    
    /// This creates a SNMP PDU data structure from the data received
    /// over the network by a SNMP reply.  Remember that the SNMP PDU
    /// is only part of the reply.
    /// - Parameter data: Received network data.
    init(data: Data) throws {
        try AsnValue.validateLength(data: data)
        guard data.count > 2 else {
            throw SnmpError.badLength
        }
        //First octet has the pdu type
        switch data[data.startIndex] {
        case 0xa1:
            self.pduType = .getNextRequest
        case 0xa2:
            self.pduType = .getResponse
        case 0xa8:
            self.pduType = .snmpReport
        default:
            throw SnmpError.unsupportedType
        }
        
        var pduPosition = try AsnValue.prefixLength(data: data) + data.startIndex
        
        let requestIdValue = try AsnValue(data: data[(pduPosition)...])
        let requestIdLength = try AsnValue.pduLength(data: data[(pduPosition)...])
        guard case .integer(let requestId) = requestIdValue else {
            throw SnmpError.unexpectedSnmpPdu
        }
        self.requestId = Int32(requestId)
        pduPosition = pduPosition + requestIdLength
        
        let errorStatusValue = try AsnValue(data: data[(pduPosition)...])
        let errorStatusLength = try AsnValue.pduLength(data: data[(pduPosition)...])
        guard case .integer(let errorStatus) = errorStatusValue else {
            throw SnmpError.unexpectedSnmpPdu
        }
        self.errorStatus = Int(errorStatus)
        pduPosition = pduPosition + errorStatusLength

        let errorIndexValue = try AsnValue(data: data[(pduPosition)...])
        let errorIndexLength = try AsnValue.pduLength(data: data[(pduPosition)...])
        guard case .integer(let errorIndex) = errorIndexValue else {
            throw SnmpError.unexpectedSnmpPdu
        }
        self.errorIndex = Int(errorIndex)
        pduPosition = pduPosition + errorIndexLength
        
        // now at variable bindings header
        var remainingVariableBindingOctets = try AsnValue.pduLength(data: data[(data.startIndex + pduPosition)...])
        let variableBindingPrefix = try AsnValue.prefixLength(data: data[(data.startIndex + pduPosition)...])
        pduPosition += variableBindingPrefix
        remainingVariableBindingOctets -= variableBindingPrefix
        let variableBinding = try SnmpVariableBinding(data: data[(data.startIndex + pduPosition)...])
        self.variableBindings = [variableBinding]
        
        //TODO for now we assume one variable binding per SNMP message
        
    }
    /// This prints out the SNMP PDU type and the OIDs and values of each variable binding.
    public var description: String {
        var result = "SNMP \(pduType) requestID: \(requestId) ErrorStatus: \(errorStatus)\n"
        for variableBinding in variableBindings {
            result += "  \(variableBinding)\n"
        }
        return result
    }
}

