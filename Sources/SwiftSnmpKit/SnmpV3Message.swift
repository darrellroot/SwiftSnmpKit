//
//  File.swift
//  
//
//  Created by Darrell Root on 7/15/22.
//

import Foundation
import CryptoKit

/// Structure for a SNMPv3 Message
/// Many properties allow internal access only for testing
public struct SnmpV3Message: CustomDebugStringConvertible {
    
    public private(set) var version: SnmpVersion = .v3
    // internal write access only for testing
    internal var messageId: Int32
    // internal acces sonly for testing
    internal var maxSize = 1400
    // for now we always send requests that are reportable in case of error

    private var reportable = true
    private var encrypted: Bool
    internal var authenticated: Bool

    private var flagsOctet: UInt8 { // octet string with 1 octet
        var flagOctet: UInt8 = 0
        if reportable {
            flagOctet += 4
        }
        if encrypted {
            flagOctet += 2
        }
        if authenticated {
            flagOctet += 1
        }
        return flagOctet
    }
    private var flagsAsn: AsnValue {
        return AsnValue.init(octetStringData: Data([flagsOctet]))
    }
    private var messageSecurityModel: UInt8 = 3

    internal private(set) var engineId: Data // example: 80000009034c710c19e30d
    private var engineIdAsn: AsnValue {
        return AsnValue(octetStringData: engineId)
    }

    internal var engineBoots = 0
    private var engineBootsAsn: AsnValue {
        return AsnValue.integer(Int64(engineBoots))
    }
    internal var engineTime = 0
    private var engineTimeAsn: AsnValue {
        return AsnValue.integer(Int64(engineTime))
    }

    private var userName: String
    private var userNameAsn: AsnValue {
        return AsnValue(octetString: userName)
    }
    //Message authentication paramters 12 octets when used
    private var authenticationParametersAsn = AsnValue(octetStringData: Data([0,0,0,0,0,0,0,0,0,0,0,0]))
    //TODO msg privacy parameters
    private var privacyParametersAsn = AsnValue(octetStringData: Data())
    private var contextName: String = ""
    private var contextNameAsn: AsnValue {
        return AsnValue.init(octetString: contextName)
    }
    internal var snmpPdu: SnmpPdu
    
    public var debugDescription: String {
        var result = "\(self.version) \(self.engineId) \(self.snmpPdu.pduType) requestId:\(self.messageId) errorStatus:\(self.snmpPdu.errorStatus) errorIndex:\(self.snmpPdu.errorIndex)\n"
        for variableBinding in self.snmpPdu.variableBindings {
            result += "  \(variableBinding)\n"
        }
        return result
    }
    
    public init?(engineId: String, userName: String, type: SnmpPduType, variableBindings: [SnmpVariableBinding], authenticationType: SnmpV3Authentication = .none, password: String? = nil) {
        let messageId = Int32.random(in: 0...Int32.max)
        self.messageId = messageId
        self.encrypted = false
        switch authenticationType {
        case .none:
            self.authenticated = false
        case .md5:
            self.authenticated = true
        case .sha1:
            self.authenticated = true
        }
        guard let engineIdData = engineId.hexstream else {
            SnmpError.log("EngineID is not hexadecimal")
            return nil
        }
        self.engineId = engineIdData
        self.userName = userName
        // for now we are setting the requestID to be the same as the snmpv3 messageid
        let snmpPdu = SnmpPdu(type: type, requestId: messageId, variableBindings: variableBindings)
        self.snmpPdu = snmpPdu
        
        switch authenticationType {
            
        case .none:
            break
        case .md5:
            guard let password = password else {
                SnmpError.log("password must not be nil when using MD5")
                return nil
            }
            let preAuthenticationData = self.asnData
            let authenticationData = SnmpV3Message.md5Parameters(messageData: preAuthenticationData, password: password, engineId: engineIdData)
            authenticationParametersAsn = AsnValue.octetString(authenticationData)

        case .sha1:
            guard let password = password else {
                SnmpError.log("password must not be nil when using SHA1")
                return nil
            }
            let preAuthenticationData = self.asnData
            let authenticationData = SnmpV3Message.sha1Parameters(messageData: preAuthenticationData, password: password, engineId: engineIdData)
            authenticationParametersAsn = AsnValue.octetString(authenticationData)
        }
    }
    internal static func passwordToShaKey(password: String, engineId: Data, algorithm: SnmpV3Authentication) -> Data {
        // https://datatracker.ietf.org/doc/html/rfc3414#appendix-A.2.2
        guard algorithm == .sha1 else {
            fatalError("passwordToShaKey algorithm must be .sha1")
        }
        guard password.count > 7 else {
            fatalError("SNMP password must be at least 8 octets")
        }
        let passwordData = password.data(using: .utf8)!
        let passwordLength = passwordData.count
        
        var circularPassword = Data(count: 64)
        var totalBytes = 0
        var sha = Insecure.SHA1()
        while totalBytes < 1048576 {
            for position in 0..<64 {
                circularPassword[position] = passwordData[totalBytes % passwordLength]
                totalBytes += 1
            }
            sha.update(data: circularPassword)
        }
        let interimShaKey = Data(sha.finalize())
        var localizedSha = Insecure.SHA1()
        localizedSha.update(data: interimShaKey)
        localizedSha.update(data: engineId)
        localizedSha.update(data: interimShaKey)
        let localizedKey = Data(localizedSha.finalize())
        return localizedKey[0..<20]
    }
    internal static func passwordToMd5Key(password: String, engineId: Data) -> Data {
        // https://datatracker.ietf.org/doc/html/rfc3414#appendix-A.2.1
        guard password.count > 7 else {
            fatalError("SNMP password must be at least 8 octets")
        }
        let passwordData = password.data(using: .utf8)!
        let passwordLength = passwordData.count
        
        var circularPassword = Data(count: 64)
        var totalBytes = 0
        var md5 = Insecure.MD5()
        while totalBytes < 1048576 {
            for position in 0..<64 {
                circularPassword[position] = passwordData[totalBytes % passwordLength]
                totalBytes += 1
            }
            md5.update(data: circularPassword)
        }
        let interimMd5Key = Data(md5.finalize())
        var localizedMd5 = Insecure.MD5()
        localizedMd5.update(data: interimMd5Key)
        localizedMd5.update(data: engineId)
        localizedMd5.update(data: interimMd5Key)
        let localizedKey = Data(localizedMd5.finalize())
        return localizedKey[0..<16]
    }
    internal static func sha1Parameters(messageData: Data, password: String, engineId: Data) -> Data {
        // utf8 encoding should never fail
        var authKeyData = SnmpV3Message.passwordToShaKey(password: password, engineId: engineId, algorithm: .sha1)
        // see https://datatracker.ietf.org/doc/html/rfc3414#section-6.3.1
        if authKeyData.count > 20 {
            authKeyData = authKeyData[0..<20]
        }
        let bytesNeeded = 64 - authKeyData.count
        let nullData = Data(count: bytesNeeded)
        authKeyData = authKeyData + nullData
        let ipad = Data(repeating: 0x36, count: 64)
        var k1 = Data(count: 64)
        let opad = Data(repeating: 0x5c, count: 64)
        var k2 = Data(count: 64)
        for position in 0..<64 {
            k1[position] = ipad[position] ^ authKeyData[position]
            k2[position] = opad[position] ^ authKeyData[position]
        }
        let digest1 = Insecure.SHA1.hash(data: k1 + messageData)
        let digest2 = Insecure.SHA1.hash(data: k2 + digest1)
        let result: Data = Data(digest2)
        //print("RESULT COUNT \(result.count)")
        return result[0..<12]
    }
    
    internal static func md5Parameters(messageData: Data, password: String, engineId: Data) -> Data {
        // utf8 encoding should never fail
        var authKeyData = SnmpV3Message.passwordToMd5Key(password: password, engineId: engineId)
        //var authKeyData = Data(capacity: 64)
        //authKeyData = authKey.data(using: .utf8)!
        // see https://datatracker.ietf.org/doc/html/rfc3414#section-6.3.1
        if authKeyData.count > 16 {
            authKeyData = authKeyData[0..<16]
        }
        let bytesNeeded = 64 - authKeyData.count
        let nullData = Data(count: bytesNeeded)
        authKeyData = authKeyData + nullData
        let ipad = Data(repeating: 0x36, count: 64)
        var k1 = Data(count: 64)
        let opad = Data(repeating: 0x5c, count: 64)
        var k2 = Data(count: 64)
        for position in 0..<64 {
            k1[position] = ipad[position] ^ authKeyData[position]
            k2[position] = opad[position] ^ authKeyData[position]
        }
        let digest1 = Insecure.MD5.hash(data: k1 + messageData)
        let digest2 = Insecure.MD5.hash(data: k2 + digest1)
        let result: Data = Data(digest2)
        print("RESULT COUNT \(result.count)")
        return result[0..<12]
    }
    


    private var usmSecurityParametersAsn: AsnValue {
        return AsnValue.sequence([engineIdAsn,engineBootsAsn,engineTimeAsn,userNameAsn,authenticationParametersAsn,privacyParametersAsn])
    }
    

    
    /// Creates SNMPv3 message data structure from the data encapsulated inside a UDP SNMP reply.
    ///
    /// Takes data from a SNMP reply and uses it to create a SNMP message data structure.  Returns nil if the data cannot form a complete SNMP reply data structure.
    /// This initializer is not designed for creating a SNMP message for transmission.
    /// - Parameter data: The network contents of a UDP reply, with the IP and UDP headers already stripped off.
    public init?(data: Data) {
        guard let outerSequence = try? AsnValue(data: data) else {
            SnmpError.log("Outer ASN is not a sequence")
            return nil
        }
        guard case .sequence(let contents) = outerSequence else {
            SnmpError.log("Unable to extract AsnValues")
            return nil
        }
        guard contents.count == 4 else {
            SnmpError.log("Expected 4 contents in SNMPv3, found \(contents.count)")
            return nil
        }
        guard case .integer(let snmpVersionInteger) = contents[0] else {
            SnmpError.log("Expected AsnInteger, got \(contents[0])")
            return nil
        }
        guard let snmpVersion = SnmpVersion(rawValue: Int(snmpVersionInteger)) else {
            SnmpError.log("Received invalid SNMP Version \(snmpVersionInteger)")
            return nil
        }
        self.version = snmpVersion
        
        guard case .sequence(let msgGlobalData) = contents[1] else {
            SnmpError.log("Expected message global data, got \(contents[1])")
            return nil
        }
        guard msgGlobalData.count == 4 else {
            SnmpError.log("Expected message global data count, got \(msgGlobalData)")
            return nil
        }
        guard case .integer(let msgId) = msgGlobalData[0] else {
            SnmpError.log("Expected messageId integer \(msgGlobalData[0])")
            return nil
        }
        self.messageId = Int32(msgId)
        guard case .integer(let maxSize) = msgGlobalData[1] else {
            SnmpError.log("Expected messageId integer got \(msgGlobalData[1])")
            return nil
        }
        self.maxSize = Int(maxSize)
        guard case .octetString(let flags) = msgGlobalData[2] else {
            SnmpError.log("Expected messageId octetString got \(msgGlobalData[2])")
            return nil
        }
        guard flags.count == 1 else {
            SnmpError.log("Expected 1 byte of messageFlags  got \(flags)")
            return nil
        }
        let flagsInt = UInt8(flags[flags.startIndex])
        if ((flagsInt & 0b00000100) > 0) {
            self.reportable = true
        } else {
            self.reportable = false
        }
        if ((flagsInt & 0b00000010) > 0) {
            self.encrypted = true
        } else {
            self.encrypted = false
        }
        if ((flagsInt & 0b00000001) > 0) {
            self.authenticated = true
        } else {
            self.authenticated = false
        }
        guard case .integer(let messageSecurityModel) = msgGlobalData[3] else {
            SnmpError.log("Expected messageSecurityModel integer got \(msgGlobalData[3])")
            return nil
        }
        guard messageSecurityModel < 256 && messageSecurityModel >= 0 else {
            SnmpError.log("Invalid messageSecurityModel \(messageSecurityModel)")
            return nil
        }
        self.messageSecurityModel = UInt8(messageSecurityModel)
        
        guard case .octetString(let securityParametersData) = contents[2] else {
            SnmpError.log("Expected octetString got \(contents[2])")
            return nil
        }
        guard case .sequence(let securityParameters) = try? AsnValue(data: securityParametersData) else {
            SnmpError.log("Expected security parametrs sequence got \(securityParametersData)")
            return nil
        }
        guard case .octetString(let engineIdOctets) = securityParameters[0] else {
            SnmpError.log("Expected security parametrs octetString got \(securityParameters[0])")
            return nil
        }
        self.engineId = engineIdOctets
        guard case .integer(let engineBoots) = securityParameters[1] else {
            SnmpError.log("Expected engineBoots Integer got \(securityParameters[1])")
            return nil
        }
        self.engineBoots = Int(engineBoots)
        guard case .integer(let engineTime) = securityParameters[2] else {
            SnmpError.log("Expected engineTime Integer got \(securityParameters[2])")
            return nil
        }
        self.engineTime = Int(engineTime)
        guard case .octetString(let usernameData) = securityParameters[3] else {
            SnmpError.log("Expected username octetString got \(securityParameters[3])")
            return nil
        }
        // utf8 string decoding should never fail
        self.userName = String(data: usernameData, encoding: .utf8)!
        guard case .octetString(let msgAuthenticationParametersData) = securityParameters[4] else {
            SnmpError.log("Expected msgAuthenticationParametersData octetString got \(securityParameters[4])")
            return nil
        }
        #warning("do something with message authentication and privacy parameters")
        guard case .octetString(let msgPrivacyParametersData) = securityParameters[5] else {
            SnmpError.log("Expected msgPrivacyParametersData octetString got \(securityParameters[5])")
            return nil
        }
        guard case .sequence(let msgData) = contents[3] else {
            SnmpError.log("Expected msgData sequence got \(contents[3])")
            return nil
        }
        guard msgData.count == 3 else {
            SnmpError.log("Expected msgData sequence size 2 got \(msgData.count)")
            return nil
        }
        guard case .octetString(let engineId2Data) = msgData[0] else {
            SnmpError.log("Expected engineId2 octetString 2 got \(msgData[0])")
            return nil
        }
        guard engineId2Data == engineIdOctets else {
            SnmpError.log("engineIds do not match! \(engineId2Data) \(engineIdOctets)")
            return nil
        }
        guard case .octetString(let contextNameData) = msgData[1] else {
            SnmpError.log("contextName expected octetString got \(msgData[1])")
            return nil
        }
        switch msgData[2] {
        case .snmpResponse(let response):
            self.snmpPdu = response
        case .snmpReport(let report):
            self.snmpPdu = report
        
        default:
            SnmpError.log("Expected SNMP response or report PDU, got \(msgData[2])")
            return nil
        }
    }
}
extension SnmpV3Message: AsnData {
    public var asn: AsnValue {
        let result = AsnValue.sequence([version.asn,msgGlobalAsn,msgSecurityParametersAsn,scopedPduAsn])
        return result
    }
    internal var asnData: Data {
        return asn.asnData
    }
    private var msgGlobalAsn: AsnValue {
        let messageIdAsn = AsnValue.integer(Int64(messageId))
        let maxSizeAsn = AsnValue.integer(Int64(maxSize))
        let securityModelAsn = AsnValue.integer(Int64(messageSecurityModel))
        let msgGlobalAsn = AsnValue.sequence([messageIdAsn,maxSizeAsn,flagsAsn,securityModelAsn])
        return msgGlobalAsn
    }
    private var scopedPduAsn: AsnValue {
        return AsnValue.sequence([engineIdAsn,contextNameAsn,snmpPdu.asn])
    }
    private var msgSecurityParametersAsn: AsnValue { return AsnValue(octetStringData: usmSecurityParametersAsn.asnData)
    }
}
/*This extension is for returning our ASN with the authentication parameters set to 12 octets of 0, so encryption can be calculated*/
extension SnmpV3Message {
    public var asnBlankAuth: AsnValue {
        let result = AsnValue.sequence([version.asn,msgGlobalAsn,msgSecurityParametersAsnBlankAuth,scopedPduAsn])
        return result
    }
    private var msgSecurityParametersAsnBlankAuth: AsnValue { return AsnValue(octetStringData: usmSecurityParametersAsnBlankAuth.asnData)
    }
    private var usmSecurityParametersAsnBlankAuth: AsnValue {
        return AsnValue.sequence([engineIdAsn,engineBootsAsn,engineTimeAsn,userNameAsn,blankAuthenticationParametersAsn,privacyParametersAsn])
    }
    private var blankAuthenticationParametersAsn: AsnValue {
        return AsnValue(octetStringData: Data([0,0,0,0,0,0,0,0,0,0,0,0]))
    }
}
