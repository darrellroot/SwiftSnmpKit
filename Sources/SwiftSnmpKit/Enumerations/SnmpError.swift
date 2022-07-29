//
//  AsnError.swift
//  Snmp1
//
//  Created by Darrell Root on 6/29/22.
//

import Foundation
public enum SnmpError: Error, LocalizedError {
    case badLength
    case invalidOid
    case unsupportedType
    case otherError
    case unexpectedSnmpPdu
    case invalidAddress
    case noResponse
    case snmpResponseError
    
    // report error types see https://oidref.com/1.3.6.1.6.3.15.1.1
    case snmpUnknownSecurityLevel
    case snmpNotInTimeWindow
    case snmpUnknownUser
    case snmpUnknownEngineId
    case snmpAuthenticationError // wrong digest
    case snmpDecryptionError
    
    public var errorDescription: String? {
        switch self {
            
        case .badLength:
            return "SnmpBadLengthError"
        case .invalidOid:
            return "SnmpInvalidOid"
        case .unsupportedType:
            return "SnmpUnsupportedTypeError"
        case .otherError:
            return "SnmpOtherError"
        case .unexpectedSnmpPdu:
            return "UnexpectedSnmpPduError"
        case .invalidAddress:
            return "SnmpInvalidAddressError"
        case .noResponse:
            return "SnmpNoResponseError"
        case .snmpResponseError:
            return "SnmpResponseError"
        case .snmpUnknownSecurityLevel:
            return "SnmpReportUnknownSecurityLevel"
        case .snmpNotInTimeWindow:
            return "SnmpReportNotInTimeWindow"
        case .snmpUnknownUser:
            return "SnmpReportUnknownUser"
        case .snmpUnknownEngineId:
            return "SnmpReportUnknownEngineId"
        case .snmpAuthenticationError:
            return "SnmpReportAuthenticationError"
        case .snmpDecryptionError:
            return "SnmpReportDecriptionError"
        }
    }
    /// This method prints out errors only if we are in debug mode
    internal static func debug(_ message: String,
            function: String = #function,
                file: String = #file,
                line: Int = #line) {
        if SnmpSender.debug == true {
            print("Error: \(file):\(function) line \(line): \(message)")
        }
    }
    /// This method prints out errors regardless of whether we are in debug mode
    internal static func log(_ message: String,
            function: String = #function,
                file: String = #file,
                line: Int = #line) {
            print("Error: \(file):\(function) line \(line): \(message)")
    }
}
