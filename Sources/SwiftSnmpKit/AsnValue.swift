//
//  AsnValue.swift
//  Snmp1
//
//  Created by Darrell Root on 6/29/22.
//  See https://luca.ntop.org/Teaching/Appunti/asn1.html

import Foundation

public enum AsnValue: Equatable, CustomStringConvertible, AsnData {
    
    static let classMask: UInt8 = 0b11000000
    
    case endOfContent
    case integer(Int64)
    #warning("TODO: Fix bitString implementation")
    case bitString(Data) // first octet indicates how many bits short of a multiple of 8 "number of unused bits". This implementation doesn't deal with this at this time
    case octetString(Data)
    case oid(SnmpOid)
    case null
    case sequence([AsnValue])
    case ia5(String)
    case snmpResponse(SnmpPdu)
    
    /// Initializes an AsnValue of type OctetString from a string.  Returns nil if the input string is not valid ASCII
    /// - Parameter octetString: This must be in ASCII format
    init?(octetString: String) {
        guard let data = octetString.data(using: .ascii) else {
            AsnError.log("Unable to encode \(octetString) in ASCII")
            return nil
        }
        self = .octetString(data)
    }
    
    /// Creates data to represent an ASN.1 length
    ///
    /// For lengths of 127 or less, this returns a single byte with that number
    /// For lengths greater than 128, it returns a byte encoding the number of bytes (with the most significant bit set), followed by the length in base-256
    /// - Parameter length: The length of data to encode
    /// - Returns: A sequence of Data bytes which represent the length
    internal static func encodeLength(_ length: Int) -> Data {
        guard length >= 0 else {
            AsnError.log("Unexpected length \(length)")
            fatalError()
        }
        if length < 128 {
            return Data([UInt8(length)])
        }
        var octetsReversed: [UInt8] = []
        var power = 0
        while (length >= SnmpUtils.powerOf256(power)) {
            octetsReversed.append(UInt8(length / SnmpUtils.powerOf256(power)))
            power += 1
        }
        
        let firstOctet = UInt8(octetsReversed.count | 0b10000000)
        let prefix = Data([firstOctet])
        let suffix = Data(octetsReversed.reversed())
        return prefix + suffix
    }
    
    /// This function encodes an OID node number in a sequence of bytes.  The encoding is done base 128.  Every octet except the last has the most significant bit set.
    /// - Parameter node: The integer representing the OID
    /// - Returns: A sequence of data bytes representing that OID in ASN.1 format
    private func encodeOidNode(node: Int) -> Data {
        var octetsReversed: [UInt8] = []
        var power = 0
        while (node >= SnmpUtils.powerOf128(power)) {
            octetsReversed.append(UInt8(node / SnmpUtils.powerOf128(power)))
            power += 1
        }
        var octets: [UInt8] = []
        for (position,octet) in octetsReversed.reversed().enumerated() {
            if position < (octetsReversed.count - 1) {
                octets.append(octet | 0b10000000)
            } else {
                octets.append(octet)
            }
        }
        return Data(octets)
    }
    internal func encodeInteger(_ value: Int64) -> Data {
        if value > -129 && value < 128 {
            let bitPattern = Int8(value)
            
            return Data([0x02,0x01,UInt8(bitPattern: bitPattern)])
        }
        let negative = value < 0
        // get bitpattern for positive, then convert if negative
        var absValue: UInt64
        if value < 0 {
            absValue = UInt64(value * -1)
        } else {
            absValue = UInt64(value)
        }
        // at first this array is reversed from what we need
        var octets: [UInt8] = []
        while absValue > 0 {
            let newOctet = UInt8(absValue % 256)
            octets.append(newOctet)
            absValue = absValue / 256
        }
        // put array with highest magnitude first
        octets.reverse()
        
        // two's complement math
        // first octet needs space for sign bit
        if octets[0] > 127 && !negative || octets[0] > 128 && negative {
            octets.insert(0, at: 0)
        }
        if negative {
            for position in 0..<octets.count {
                octets[position] = ~octets[position]
            }
            var position = octets.count - 1
            var done = false
            while !done {
                if position < 0 {
                    // need to add an octet
                    octets = [1] + octets
                    done = true
                } else if octets[position] < 255 {
                    octets[position] = octets[position] + 1
                    done = true
                } else {
                    octets[position] = 0
                    position = position - 1
                }
            }
        }
        let lengthOctets = AsnValue.encodeLength(octets.count)
        return Data([0x02]) + lengthOctets + octets
    }
    /// Creates a Data array from an unsigned integer.  Base 128.  Every octet except the last has most significant bit set to 1.  Used to encode OIDs
    /// - Parameter value: Positive integer
    /// - Returns: Data array encoding integer base 128 with most significant bits set to 1
    internal static func base128ToData(_ value: Int) -> Data {
        if value == 0 {
            return Data([0])
        }
        var result = Data() // initially in reverse order
        var value = value
        while value > 0 {
            result.append(UInt8(value % 128))
            value = value / 128
        }
        result.reverse() // most significant octet now leading
        // set most significant bit in every octet except last
        for position in 0..<(result.count - 1) {
            result[position] = result[position] | 0b10000000
        }
        return result
    }

    internal var asnData: Data {
        switch self {
            
        case .endOfContent:
            return Data([])
        case .integer(let value):
            return encodeInteger(value)
        case .bitString(let data):
            let lengthData = AsnValue.encodeLength(data.count)
            let prefix = Data([0x03])
            return prefix + lengthData + data
        case .octetString(let octets):
            let lengthData = AsnValue.encodeLength(octets.count)
            let prefix = Data([0x04])
            return prefix + lengthData + octets
        case .oid(let oid):
            return oid.asnData
        case .null:
            return Data([0x05,0x00])
        case .sequence(let contents):
            var contentData = Data()
            for content in contents {
                contentData += content.asnData
            }
            let lengthData = AsnValue.encodeLength(contentData.count)
            let prefix = Data([0x30])
            return prefix + lengthData + contentData
        case .ia5(let string):
            // only valid if string characters are ascii
            // we will warn, and then encode as UTF-8 anyway rather than crash
            if string.data(using: .ascii) == nil {
                AsnError.log("Unable to encode ia5 string \(string) as ASCII")
            }
            guard let stringData = string.data(using: .utf8) else {
                // the above line should never fail
                fatalError("Unexpectedly unable to convert \(string) to utf-8 encoding")
            }
            let lengthData = AsnValue.encodeLength(stringData.count)
            let prefix = Data([0x16])
            return prefix + lengthData + stringData
        case .snmpResponse(let response):
            let prefix = Data([0xa2])
            let requestIdData = AsnValue.integer(Int64(response.requestId)).asnData
            let errorStatusData = AsnValue.integer(Int64(response.errorStatus)).asnData
            let errorIndexData = AsnValue.integer(Int64(response.errorIndex)).asnData
            
            
            return Data()
            #warning("TODO")
            break
        }
    }
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
