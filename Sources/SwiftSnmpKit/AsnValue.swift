//
//  AsnValue.swift
//  Snmp1
//
//  Created by Darrell Root on 6/29/22.
//

import Foundation

public enum AsnValue: Equatable, CustomStringConvertible {
    
    static let classMask: UInt8 = 0b11000000
    
    case endOfContent
    case boolean(Bool)
    case integer(Int64)
    case bitString(Data)
    case octetString(Data)
    case oid(SnmpOid)
    case null
    case sequence([AsnValue])
    case ia5(String)
    case snmpResponse(SnmpPdu)
    
    static func pduLength(data: Data) throws -> Int {
        /* Input: The start of an ASN1 value
         Output: The length of the value
         Errors: If the size of the data is insufficient for the PDU, it throws an error */
        try validateLength(data: data)
        let prefixLength = try prefixLength(data: data)
        let valueLength = try valueLength(data: data[(data.startIndex + 1)...])
        return prefixLength + valueLength
    }
    static func validateLength(data: Data) throws {
        /* this function validates that there are sufficient data octets to read the type, length, and value, preventing a crash */
        guard data.count > 1 else {
            throw AsnError.badLength
        }
        let valueLength = try AsnValue.valueLength(data: data[(data.startIndex+1)...])
        let prefixLength = try AsnValue.prefixLength(data: data)
        guard data.count >= valueLength + prefixLength else {
            throw AsnError.badLength
        }
    }
    init(data: Data) throws {
        guard data.count > 0 else {
            throw AsnError.badLength
        }
        let identifierOctet = data[data.startIndex]
        
        switch identifierOctet {
        case 2: // ASN1 Integer
            try AsnValue.validateLength(data: data)
            let integerLength = try AsnValue.valueLength(data: data[(data.startIndex+1)...])
            let prefixLength = try AsnValue.prefixLength(data: data)
            let firstNumericOctet = data[data.startIndex + prefixLength]
            // checking two's complement sign
            let negative: Bool = firstNumericOctet & 0b10000000 > 0
            var magnitude = Int64(firstNumericOctet & 0b01111111)
            
            for octet in data[(data.startIndex + prefixLength + 1)..<(data.startIndex + prefixLength + integerLength)] {
                // use bitshifiting to multiply by 256
                magnitude = (magnitude << 8)
                magnitude = magnitude + Int64(octet)
            }
            // Two's complement by adding magnitude to -(256^digits)
            if negative {
                var lowerbound: Int64 = -128
                for _ in 1..<integerLength {
                    lowerbound = lowerbound * 256
                }
                magnitude = lowerbound + magnitude
            }
            self = .integer(magnitude)
            return
        case 4:
            // Octet String
            guard data.count > 1 else {
                throw AsnError.badLength
            }
            let stringLength = try AsnValue.valueLength(data: data[(data.startIndex+1)...])
            let prefixLength = try AsnValue.prefixLength(data: data)
            guard data.count >= stringLength + prefixLength else {
                throw AsnError.badLength
            }
            let stringData = data[(data.startIndex + prefixLength)..<(data.startIndex + prefixLength + stringLength)]
            //let string = String(decoding: stringData, as: UTF8.self)
            self = .octetString(stringData)
        case 5: // ASN1 Null
            self = .null
            return
        case 6: // OID
            try AsnValue.validateLength(data: data)
            let prefixLength = try AsnValue.prefixLength(data: data)
            let valueLength = try AsnValue.valueLength(data: data.advanced(by: 1))
            let firstOctet = data[data.startIndex + prefixLength]
            var result: [Int] = []
            // special ASN rules for first two octets
            result.append(Int(firstOctet) / 40)
            result.append(Int(firstOctet) % 40)
            var nextValue = 0
            for octet in data[(data.startIndex + prefixLength + 1) ..< (data.startIndex + prefixLength + valueLength)] {
                // base 128 math.  Each number ends when most significant bit is not set
                if octet > 127 {
                    nextValue = nextValue * 128 + Int(octet) - 128
                } else {
                    nextValue = nextValue * 128 + Int(octet)
                    result.append(nextValue)
                    nextValue = 0
                }
            }
            guard let oid = SnmpOid(nodes: result) else {
                throw AsnError.unexpectedSnmpPdu
            }
            self = .oid(oid)
            return
        case 22: // ASN1 IA5 (ASCII) encoding
            guard data.count > 1 else {
                throw AsnError.badLength
            }
            let stringLength = try AsnValue.valueLength(data: data[(data.startIndex+1)...])
            let prefixLength = try AsnValue.prefixLength(data: data)
            guard data.count >= stringLength + prefixLength else {
                throw AsnError.badLength
            }
            let stringData = data[(data.startIndex + prefixLength)..<(data.startIndex + prefixLength + stringLength)]
            let string = String(decoding: stringData, as: UTF8.self)
            self = .ia5(string)
        case 16,48: // sequence of
            try AsnValue.validateLength(data: data)
            let prefixLength = try AsnValue.prefixLength(data: data)
            let pduLength = try AsnValue.pduLength(data: data)
            var contentData = data[(data.startIndex + prefixLength)..<(data.startIndex + pduLength)]
            var contents: [AsnValue] = []
            while (contentData.count > 0) {
                let newValueLength = try AsnValue.pduLength(data: contentData)
                let newValue = try AsnValue(data: contentData)
                contents.append(newValue)
                contentData = contentData.advanced(by: newValueLength)
            }
            self = .sequence(contents)
            return
        case 0xa2: // SNMP Response PDU
            try AsnValue.validateLength(data: data)
            //let prefixLength = try AsnValue.prefixLength(data: data)
            let pduLength = try AsnValue.pduLength(data: data)
            let pduData = data[(data.startIndex)..<(data.startIndex + pduLength)]
            let pdu = try SnmpPdu(data: pduData)
            self = .snmpResponse(pdu)
            return
        default:
            debugPrint("Unexpected identifier octet \(identifierOctet)")
            throw AsnError.unsupportedType
        }
    }
    
    static func prefixLength(data: Data) throws -> Int {
        // input: the Data starting with the ASN1 type octet to be analyzed
        // output: the count of the type and length octets.  In other words how many octets to skip to get to the data
        guard data.count > 1 else {
            throw AsnError.badLength
        }
        if data[data.startIndex+1] < 128 {
            return 2
        } else {
            return Int(data[data.startIndex+1]) - 126
        }
    }
    static func valueLength(data: Data) throws -> Int {
        // pass the octet that starts the length term
        // returns number of data octets which encodes the value using BER rules.  does not include the type or length fields itself
        guard data.count > 0 else {
            AsnError.log("Bad length length \(data.hexdump)")
            throw AsnError.badLength
        }
        let firstOctet = data[data.startIndex]
        guard firstOctet > 127 else {
            return Int(firstOctet)
        }
        let numberLengthBytes = Int(firstOctet & 0b01111111)
        guard data.count > numberLengthBytes else {
            AsnError.log("Invalid Length \(data.hexdump)")
            throw AsnError.badLength
        }
        var length = Int(data[data.startIndex + 1])
        for position in 2..<(numberLengthBytes+1) {
            length = length * 256 + Int(data[data.startIndex + position])
        }
        return length
    }
    
    public var description: String {
        switch self {
            
        case .endOfContent:
            return "EndOfContent"
        case .boolean(let bool):
            return "Bool: \(bool)"
        case .integer(let integer):
            return "Integer: \(integer)"
        case .bitString(let bitString):
            return "BitString: \(bitString)"
        case .octetString(let octetString):
            return "OctetString: \(octetString)"
        case .oid(let oid):
            return "Oid: \(oid)"
        case .null:
            return "Null"
        case .sequence(let contents):
            var result = "Sequence:\n"
            for content in contents {
                result += "  \(content)\n"
            }
            return result
        case .ia5(let string):
            return "IA5: \(string)"
        case .snmpResponse(let response):
            return "SNMP Response (contents deleted)"
        }
    }

}
