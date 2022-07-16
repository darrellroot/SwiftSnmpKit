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


    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
