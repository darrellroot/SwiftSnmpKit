//
//  File.swift
//  
//
//  Created by Darrell Root on 7/15/22.
//

import Foundation

/// Structure for a SNMPv3 Message
public struct SnmpV3Message: AsnData {
    public private(set) var version: SnmpVersion = .v3
    internal private(set) var messageId: Int32

    private var maxSize = 1400
    // for now we always send requests that are reportable in case of error

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

    private var engineId: Data // example: 80000009034c710c19e30d
    private var engineIdAsn: AsnValue {
        return AsnValue(octetStringData: engineId)
    }

    private var engineBoots = 0
    private var engineBootsAsn: AsnValue {
        return AsnValue.integer(Int64(engineBoots))
    }
    private var engineTime = 0
    private var engineTimeAsn: AsnValue {
        return AsnValue.integer(Int64(engineTime))
    }

    private var userName: String
    private var userNameAsn: AsnValue {
        return AsnValue(octetString: userName)
    }
    //TODO msg authentication parameters
    private var authenticationParametersAsn = AsnValue(octetStringData: Data())
    //TODO msg privacy parameters
    private var privacyParametersAsn = AsnValue(octetStringData: Data())
    private var contextName: String = ""
    private var contextNameAsn: AsnValue {
        return AsnValue.init(octetString: contextName)
    }
    private var snmpPdu: SnmpPdu
    
    public init?(engineId: String, userName: String, type: SnmpPduType, variableBindings: [SnmpVariableBinding]) {
        let messageId = Int32.random(in: 0...Int32.max)
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
    
    private var usmSecurityParametersAsn: AsnValue {
        return AsnValue.sequence([engineIdAsn,engineBootsAsn,engineTimeAsn,userNameAsn,authenticationParametersAsn,privacyParametersAsn])
    }
    private var msgSecurityParametersAsn: AsnValue { return AsnValue(octetStringData: usmSecurityParametersAsn.asnData)
    }
    
    private var scopedPduAsn: AsnValue {
        return AsnValue.sequence([engineIdAsn,contextNameAsn,snmpPdu.asn])
    }
    /*private var snmpPduInOctetStringAsn: AsnValue {
        return AsnValue(octetStringData: snmpPdu.asnData)
    }*/
    
    public var asn: AsnValue {
        let result = AsnValue.sequence([version.asn,msgGlobalAsn,msgSecurityParametersAsn,scopedPduAsn])
        return result
    }
    
    internal var asnData: Data {
        return asn.asnData
    }
    
    
}
