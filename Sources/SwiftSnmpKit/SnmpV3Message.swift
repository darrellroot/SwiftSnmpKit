//
//  File.swift
//  
//
//  Created by Darrell Root on 7/15/22.
//

import Foundation
import CryptoKit
import CryptoSwift

/// Structure for a SNMPv3 Message
/// Many properties allow internal access only for testing
public struct SnmpV3Message: CustomDebugStringConvertible {
    

    
    public private(set) var version: SnmpVersion = .v3
    // internal write access only for testing
    internal var messageId: Int32
    // internal access sonly for testing
    internal var maxSize = 1400
    // for now we always send requests that are reportable in case of error
    
    internal var authPassword: String? // non-nil for sending authenticated messages
    internal var privPassword: String? // non-nil will trigger AES
    internal var privParameters: Data
    internal var localizedPrivKey: Data {
        guard let privPassword = privPassword else {
            fatalError("\(#function) should only be called if privPassword != nil")
        }
        switch self.authenticationType {
        case .noAuth, .yes:
            fatalError("\(#function) should only be called if authentication is defined")
        case .md5:
            return SnmpV3Message.passwordToMd5Key(password: privPassword, engineId: self.engineId)
        case .sha1:
            return SnmpV3Message.passwordToSha1Key(password: privPassword, engineId: self.engineId)
        case .sha256:
            return SnmpV3Message.passwordToSha256Key(password: privPassword, engineId: self.engineId)
        }
    }
    // see https://www.ietf.org/rfc/rfc3826.txt section 3.1.2.1
    internal var privInitializationVector: Data {
        return self.engineBoots.bigEndianData + self.engineTime.bigEndianData + self.privParameters
    }
    private var reportable = true
    private var encrypted: Bool
    internal var authenticated: Bool {
        if self.authenticationType == .noAuth {
            return false
        } else {
            return true
        }
    }
    internal var authenticationType: SnmpV3Authentication
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
    internal var engineBoots: Int
    private var engineBootsAsn: AsnValue {
        return AsnValue.integer(Int64(engineBoots))
    }
    internal var engineTime: Int
    private var engineTimeAsn: AsnValue {
        return AsnValue.integer(Int64(engineTime))
    }

    private var userName: String
    private var userNameAsn: AsnValue {
        return AsnValue(octetString: userName)
    }
    //Message authentication paramters 12 octets when used
    /*private var authenticationParametersAsn = AsnValue(octetStringData: Data([0,0,0,0,0,0,0,0,0,0,0,0]))*/
    private var privacyParametersAsn: AsnValue {
        return AsnValue(octetStringData: self.privParameters)
    }
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
    
    public init?(engineId: String, userName: String, type: SnmpPduType, variableBindings: [SnmpVariableBinding], authenticationType: SnmpV3Authentication = .noAuth, authPassword: String? = nil, privPassword: String? = nil, engineBoots: Int, engineTime: Int) {
        let messageId = Int32.random(in: 0...Int32.max)
        self.messageId = messageId
        self.authenticationType = authenticationType
        guard let engineIdData = engineId.hexstream else {
            SnmpError.log("EngineID is not hexadecimal")
            return nil
        }
        self.engineId = engineIdData
        self.engineBoots = engineBoots
        self.engineTime = engineTime
        self.userName = userName
        // for now we are setting the requestID to be the same as the snmpv3 messageid
        let snmpPdu = SnmpPdu(type: type, requestId: messageId, variableBindings: variableBindings)
        self.snmpPdu = snmpPdu
        
        self.authPassword = authPassword
        if authPassword == nil && authenticationType != .noAuth {
            SnmpError.log("password must not be nil when using authentication")
            return nil
        }
        self.privPassword = privPassword
        if privPassword != nil && authenticationType == .noAuth {
            SnmpError.log("SNMP privacy mode requires authentication")
            return nil
        }
        if privPassword == nil {
            self.encrypted = false
            self.privParameters = Data()
        } else {
            self.encrypted = true
            var privData = Data(count: 8)
            for position in 0..<8 {
                privData[position] = UInt8.random(in: 0...255)
            }
            self.privParameters = privData
        }
    }
    // I would love to make this generic to handle any sha
    // but had trouble
    internal static func passwordToSha1Key(password: String, engineId: Data) -> Data {
        // https://datatracker.ietf.org/doc/html/rfc3414#appendix-A.2.2
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
    // I would love to make this generic to handle any sha
    // but had trouble
    // see https://datatracker.ietf.org/doc/html/rfc7630#page-6
    internal static func passwordToSha256Key(password: String, engineId: Data) -> Data {
        // https://datatracker.ietf.org/doc/html/rfc3414#appendix-A.2.2
        guard password.count > 7 else {
            fatalError("SNMP password must be at least 8 octets")
        }
        let passwordData = password.data(using: .utf8)!
        let passwordLength = passwordData.count
        
        var circularPassword = Data(count: 64)
        var totalBytes = 0
        var sha = SHA256()
        while totalBytes < 1048576 {
            for position in 0..<64 {
                circularPassword[position] = passwordData[totalBytes % passwordLength]
                totalBytes += 1
            }
            sha.update(data: circularPassword)
        }
        let interimShaKey = Data(sha.finalize())
        var localizedSha = SHA256()
        localizedSha.update(data: interimShaKey)
        localizedSha.update(data: engineId)
        localizedSha.update(data: interimShaKey)
        let localizedKey = Data(localizedSha.finalize())
        return localizedKey[0..<32]
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
        var authKeyData = SnmpV3Message.passwordToSha1Key(password: password, engineId: engineId)
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
    
    internal static func sha256Parameters(messageData: Data, password: String, engineId: Data) -> Data {
        // utf8 encoding should never fail
        let expectedAuthKeyLength = 32 // for SHA256
        var authKeyData = SnmpV3Message.passwordToSha256Key(password: password, engineId: engineId)
        // see https://datatracker.ietf.org/doc/html/rfc3414#section-6.3.1
        if authKeyData.count > expectedAuthKeyLength {
            authKeyData = authKeyData[0..<expectedAuthKeyLength]
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
        let digest1 = SHA256.hash(data: k1 + messageData)
        let digest2 = SHA256.hash(data: k2 + digest1)
        let result: Data = Data(digest2)
        //print("RESULT COUNT \(result.count)")
        return result[0..<24]
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
        let authenticationParametersAsn: AsnValue
        switch self.authenticationType {
        case .noAuth:
            return AsnValue.sequence([engineIdAsn,engineBootsAsn,engineTimeAsn,userNameAsn,blankAuthenticationParametersAsn,privacyParametersAsn])
        case .yes:
            SnmpError.log(".yes is invalid for generating authentication, trying to continue")
            return AsnValue.sequence([engineIdAsn,engineBootsAsn,engineTimeAsn,userNameAsn,blankAuthenticationParametersAsn,privacyParametersAsn])
        case .md5:
            fatalError("not implemented")
        case .sha1:
            let blankData = asnBlankAuth.asnData
            guard let password = authPassword else {
                SnmpError.log("Unable to generate authentication data without a password")
                return AsnValue.sequence([engineIdAsn,engineBootsAsn,engineTimeAsn,userNameAsn,blankAuthenticationParametersAsn,privacyParametersAsn])
            }
            let authData =
            SnmpV3Message.sha1Parameters(messageData: blankData, password: password, engineId: self.engineId)
            let authenticationParameters = AsnValue(octetStringData: authData)
            return AsnValue.sequence([engineIdAsn,engineBootsAsn,engineTimeAsn,userNameAsn,authenticationParameters,privacyParametersAsn])
        case .sha256:
            let blankData = asnBlankAuth.asnData
            guard let password = authPassword else {
                SnmpError.log("Unable to generate authentication data without a password")
                return AsnValue.sequence([engineIdAsn,engineBootsAsn,engineTimeAsn,userNameAsn,blankAuthenticationParametersAsn,privacyParametersAsn])
            }
            let authData =
            SnmpV3Message.sha256Parameters(messageData: blankData, password: password, engineId: self.engineId)
            let authenticationParameters = AsnValue(octetStringData: authData)
            return AsnValue.sequence([engineIdAsn,engineBootsAsn,engineTimeAsn,userNameAsn,authenticationParameters,privacyParametersAsn])
        }
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
            self.authenticationType = .yes
        } else {
            self.authenticationType = .noAuth
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
        guard case .octetString(let msgPrivacyParametersData) = securityParameters[5] else {
            SnmpError.log("Expected msgPrivacyParametersData octetString got \(securityParameters[5])")
            return nil
        }
        self.privParameters = msgPrivacyParametersData
        let msgDataSequence: AsnValue
        if case .octetString(let encryptedContents) = contents[3] {
            let engineBootsData = Int(engineBoots).bigEndianData
            let engineTimeData = Int(engineTime).bigEndianData
            let privInitializationVector = engineBootsData + engineTimeData + msgPrivacyParametersData
            guard privInitializationVector.count == 16 else {
                SnmpError.log("Invalid initialization vector \(data)")
                return nil
            }
            guard let localizedKey = SnmpSender.shared?.localizedKeys[messageId] else {
                SnmpError.log("Unable to find decryption key for messageId \(messageId)")
                return nil
            }
            SnmpSender.shared?.localizedKeys[messageId] = nil
            do {
                let aes = try AES(key: localizedKey, blockMode: CFB(iv: [UInt8](privInitializationVector)))
                let msgUInt = try aes.decrypt([UInt8](encryptedContents))
                let msgDataTemp = Data(msgUInt)
                msgDataSequence = try AsnValue(data: msgDataTemp)
            } catch (let error) {
                SnmpError.log("SNMPv3 decryption error: \(error)")
                return nil
            }
        } else {
            msgDataSequence = contents[3]
        }
        guard case .sequence(let msgData) = msgDataSequence else { // was contents[3]
            SnmpError.log("Expected msgData sequence or encrypted octetData got \(contents[3])")
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
    internal var asn: AsnValue {
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
        if privPassword == nil {
            return AsnValue.sequence([engineIdAsn,contextNameAsn,snmpPdu.asn])
        } else {
            // we need to encrypt
            let scopedPduData = AsnValue.sequence([engineIdAsn,contextNameAsn,snmpPdu.asn]).asnData
            do {
                let key: [UInt8] = [UInt8](localizedPrivKey[0..<16])
                let aes = try AES(key: key, blockMode: CFB(iv: [UInt8](privInitializationVector)))
                let encryptedPdu = try aes.encrypt([UInt8](scopedPduData))
                let result = AsnValue.init(octetStringData: Data(encryptedPdu))
                SnmpSender.shared?.localizedKeys[self.messageId] = key
                return result
            } catch(let error) {
                SnmpError.log("Failed to encrypt data: \(error)")
                fatalError("this is bad")
            }
        }
    }
    private var msgSecurityParametersAsn: AsnValue { return AsnValue(octetStringData: usmSecurityParametersAsn.asnData)
    }
}
/*This extension is for returning our ASN with the authentication parameters set to 12 octets of 0, so authentication can be calculated*/
extension SnmpV3Message {
    internal var asnBlankAuth: AsnValue {
        let result = AsnValue.sequence([version.asn,msgGlobalAsn,msgSecurityParametersAsnBlankAuth,scopedPduAsn])
        return result
    }
    private var msgSecurityParametersAsnBlankAuth: AsnValue { return AsnValue(octetStringData: usmSecurityParametersAsnBlankAuth.asnData)
    }
    private var usmSecurityParametersAsnBlankAuth: AsnValue {
        return AsnValue.sequence([engineIdAsn,engineBootsAsn,engineTimeAsn,userNameAsn,blankAuthenticationParametersAsn,privacyParametersAsn])
    }
    private var blankAuthenticationParametersAsn: AsnValue {
        switch self.authenticationType {
        case .sha1:
            return AsnValue(octetStringData: Data([0,0,0,0,0,0,0,0,0,0,0,0]))
        case .sha256:
            return AsnValue(octetStringData: Data(count: 24))
        default:
            return AsnValue(octetStringData: Data())
        }
    }
}
