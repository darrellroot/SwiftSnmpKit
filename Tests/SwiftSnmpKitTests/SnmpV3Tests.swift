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

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
