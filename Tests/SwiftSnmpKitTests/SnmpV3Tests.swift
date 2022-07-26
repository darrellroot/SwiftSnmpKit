//
//  SnmpV3Tests.swift
//  SwiftSnmpKitTests
//
//  Created by Darrell Root on 7/15/22.
//

import XCTest
@testable import SwiftSnmpKit

class SnmpV3Tests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testV3one() throws {
        let variableBinding = SnmpVariableBinding(oid: SnmpOid("1.3.6")!)
        let snmpV3Message = SnmpV3Message(engineId: "80000009034c710c19e30d", userName: "ciscouser", type: .getNextRequest, variableBindings: [variableBinding])!
        let snmpV3Asn = snmpV3Message.asn
        let data = snmpV3Asn.asnData
        //sequence, snmp version, sequence, start of msgID
        //XCTAssert(data[0..<9] == "306402010330110204".hexstream!)
        print(data.hexdump)
    }
    /*
     Simple Network Management Protocol
         msgVersion: snmpv3 (3)
         msgGlobalData
             msgID: 47813554
             msgMaxSize: 1400
             msgFlags: 00
                 .... .0.. = Reportable: Not set
                 .... ..0. = Encrypted: Not set
                 .... ...0 = Authenticated: Not set
             msgSecurityModel: USM (3)
         msgAuthoritativeEngineID: 80000009034c710c19e30d
             1... .... = Engine ID Conformance: RFC3411 (SNMPv3)
             Engine Enterprise ID: ciscoSystems (9)
             Engine ID Format: MAC address (3)
             Engine ID Data: MAC address: Cisco_19:e3:0d (4c:71:0c:19:e3:0d)
         msgAuthoritativeEngineBoots: 0
         msgAuthoritativeEngineTime: 0
         msgUserName: ciscouser
         msgAuthenticationParameters: <MISSING>
         msgPrivacyParameters: <MISSING>
         msgData: plaintext (0)
             plaintext
                 contextEngineID: 80000009034c710c19e30d
                 contextName:
                 data: get-response (2)
                     get-response
                         request-id: 47813554
                         error-status: noError (0)
                         error-index: 0
                         variable-bindings: 1 item
                             1.3.6.1.2.1.1.1.0: "SG250-08 8-Port Gigabit Smart Switch"
                 [Response To: 1]
                 [Time: 0.004505000 seconds]
     */
    func testSnmpV31() throws {
        let data = "30818e0201033010020402d993b20202057804010002010304243022040b80000009034c710c19e30d0201000201000409636973636f75736572040004003051040b80000009034c710c19e30d0400a240020402d993b20201000201003032303006082b06010201010100042453473235302d303820382d506f7274204769676162697420536d61727420537769746368".hexstream!
        guard let snmpMessageV3 = SnmpV3Message(data: data) else {
            XCTFail()
            return
        }
        XCTAssert(snmpMessageV3.messageId == 47813554)
        XCTAssert(snmpMessageV3.version == .v3)
    }
    
    func testReport1() throws {
        let data = "306d020103301002041814e0360202057804010002010304243022040b80000009034c710c19e30d0201000201000409636973636f75736572040004003030040b80000009034c710c19e30d0400a81f02041814e0360201000201003011300f060a2b060106030f01010100410101".hexstream!
        guard let snmpMessageV3 = SnmpV3Message(data: data) else {
            XCTFail()
            return
        }
    }
    
    /*
     Frame 19: 165 bytes on wire (1320 bits), 165 bytes captured (1320 bits) on interface en0, id 0
     Ethernet II, Src: Apple_28:3a:6d (3c:22:fb:28:3a:6d), Dst: Cisco_19:e3:0d (4c:71:0c:19:e3:0d)
     Internet Protocol Version 4, Src: 192.168.4.23 (192.168.4.23), Dst: 192.168.4.120 (192.168.4.120)
     User Datagram Protocol, Src Port: 51064, Dst Port: 161
     Simple Network Management Protocol
         msgVersion: snmpv3 (3)
         msgGlobalData
             msgID: 1395354433
             msgMaxSize: 65507
             msgFlags: 05
                 .... .1.. = Reportable: Set
                 .... ..0. = Encrypted: Not set
                 .... ...1 = Authenticated: Set
             msgSecurityModel: USM (3)
         msgAuthoritativeEngineID: 80000009034c710c19e30d
             1... .... = Engine ID Conformance: RFC3411 (SNMPv3)
             Engine Enterprise ID: ciscoSystems (9)
             Engine ID Format: MAC address (3)
             Engine ID Data: MAC address: Cisco_19:e3:0d (4c:71:0c:19:e3:0d)
         msgAuthoritativeEngineBoots: 1
         msgAuthoritativeEngineTime: 619360
         msgUserName: ciscoauth
         msgAuthenticationParameters: 0465a70fff9c27e0e5795837
         msgPrivacyParameters: <MISSING>
         msgData: plaintext (0)
             plaintext
                 contextEngineID: 80000009034c710c19e30d
                     1... .... = Engine ID Conformance: RFC3411 (SNMPv3)
                     Engine Enterprise ID: ciscoSystems (9)
                     Engine ID Format: MAC address (3)
                     Engine ID Data: MAC address: Cisco_19:e3:0d (4c:71:0c:19:e3:0d)
                 contextName:
                 data: get-request (0)
                     get-request
                         request-id: 540067032
                         error-status: noError (0)
                         error-index: 0
                         variable-bindings: 1 item
                             1.3.6.1.2.1.1.1.0: Value (Null)
                                 Object Name: 1.3.6.1.2.1.1.1.0 (iso.3.6.1.2.1.1.1.0)
                                 Value (Null)
                 [Response In: 20]
     */
    func testAuthentication1() throws {
        let snmpData = "307902010330110204532b6b41020300ffe304010502010304323030040b80000009034c710c19e30d02010102030973600409636973636f61757468040c0000000000000000000000000400302d040b80000009034c710c19e30d0400a01c02042030c4d8020100020100300e300c06082b060102010101000500".hexstream!
        let password = "authkey1auth"
        let expectedResult = "0465a70fff9c27e0e5795837".hexstream!
        let engineId = "80000009034c710c19e30d".hexstream!
        let actualResult = SnmpV3Message.md5(messageData: snmpData, password: password, engineId: engineId)
        XCTAssert(expectedResult == actualResult)
    }
    
    func testPasswordToKey() throws {
        // from https://datatracker.ietf.org/doc/html/rfc3414#page-81 A.3.1
        let password = "maplesyrup"
        let key = SnmpV3Message.passwordToMd5Key(password: password, engineId: Data([0,0,0,0,0,0,0,0,0,0,0,2]))
        XCTAssert(key == Data([0x52,0x6f,0x5e,0xed,0x9f,0xcc,0xe2,0x6f,0x89,0x64,0xc2,0x93,0x07,0x87,0xd8,0x2b]))
        //This is the non-localized result
        //XCTAssert(key == Data([0x9f,0xaf,0x32,0x83,0x88,0x4e,0x92,0x83,0x4e,0xbc,0x98,0x47,0xd8,0xed,0xd9,0x63]))
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
