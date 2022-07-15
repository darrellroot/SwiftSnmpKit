//
//  File.swift
//  
//
//  Created by Darrell Root on 7/15/22.
//

import Foundation

/// Structure for a SNMPv3 Message
struct SnmpV3Message {
    public private(set) var version: SnmpVersion = .v3
    private var messageId: Int32
    private var messageIdData: Data {
        return AsnValue.integer(Int64(messageId)).asnData
    }
    private var maxSize = 1400
    // for now we always send requests that are reportable in case of error
    private var maxSizeData: Data {
        return AsnValue.integer(Int64(maxSize)).asnData
    }
    private var reportable = true
    private var encrypted: Bool
    private var authenticated: Bool

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
    private let messageSecurityModel: UInt8 = 3
    private var messageSecurityModelData: Data { return Data([0x02,0x01,messageSecurityModel])
    }
    private var engineId: Data // example: 80000009034c710c19e30d
    private var engineIdData: Data {
        let octetString = AsnValue(octetStringData: engineId)
        return octetString.asnData
    }
    private var engineBoots = 0
    private var engineBootsData: Data {
        let engineBootsAsn = AsnValue.integer(Int64(engineBoots))
        return engineBootsAsn.asnData
    }
    private var engineTime = 0
    private var engineTimeData: Data {
        let engineTimeAsn = AsnValue.integer(Int64(engineTime))
        return engineTimeAsn.asnData
    }
    private var userName: String
    private var userNameData: Data {
        let userNameAsn = AsnValue(octetString: userName)
        return userNameAsn.asnData
    }
    //TODO msg authentication parameters
    private var authenticationParametersData = Data([0x04,0x00])
    //TODO msg privacy parameters
    private var privacyParametersData = Data([0x04,0x00])
    //TODO contextName
    private var contextNameData = Data([0x04,0x00])
    private var snmpPdu: SnmpPdu
    
    init?(engineId: String, userName: String, type: SnmpPduType, variableBindings: [SnmpVariableBinding]) {
        let messageId = Int32.random(in: Int32.min...Int32.max)
        self.messageId = messageId
        self.encrypted = false
        self.authenticated = false
        guard let engineIdData = engineId.hexstream else {
            SnmpError.log("EngineID is not hexadecimal")
            return nil
        }
        self.engineId = engineIdData
        self.userName = userName
        // for now we are setting the requestID to be the same as the snmpv3 messageid
        let snmpPdu = SnmpPdu(type: type, requestId: messageId, variableBindings: variableBindings)
        self.snmpPdu = snmpPdu
    }
    
    private var msgGlobalAsn: AsnValue {
        let messageIdAsn = AsnValue.integer(Int64(messageId))
        let maxSizeAsn = AsnValue.integer(Int64(maxSize))
        let securityModelAsn = AsnValue.integer(Int64(messageSecurityModel))
        let msgGlobalAsn = AsnValue.sequence([messageIdAsn,maxSizeAsn,flagsAsn,securityModelAsn])
        return msgGlobalAsn
    }
    
    public var asnData: Data {
        var contentsData = self.snmpVersion.asnData +
    }
    
    
}
