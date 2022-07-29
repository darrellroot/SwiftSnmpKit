//
//  SnmpAgentTests.swift
//  
//
//  Created by Darrell Root on 7/29/22.
//

import XCTest
import SwiftSnmpKit

/// This set of tests requires you to setup a SNMP agent in your network
/// Preferably with a SNMPv3 user per authentication type
class SnmpAgentTests: XCTestCase {
    let agent = "192.168.4.120"
    let community = "public"
    struct V3parameters {
        let username: String
        let password: String?
        let authentication: SnmpV3Authentication
    }
    let testUsers: [V3parameters] = [
        V3parameters(username: "ciscogroup", password: nil, authentication: .noAuth),
        V3parameters(username: "ciscoauth", password: "authkey1auth", authentication: .sha1),
    ]

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testV2Get1() async throws {
        let oid = "1.3.6.1.2.1.1.1.0"

        let result = await SnmpSender.shared!.send(host: agent, command: .getRequest, community: community, oid: oid)
        switch result {
        case .failure(let error):
            print("test failure: \(error.localizedDescription)")
            XCTFail()
            return
        case .success(let variableBinding):
            guard variableBinding.oid == SnmpOid(oid)! else {
                XCTFail()
                return
            }
            print("test success: \(variableBinding)")
            return
        }
    }
    func testv3get1() async throws {
        let oid = "1.3.6.1.2.1.1.1.0"

        for user in testUsers.shuffled() {
            let result = await SnmpSender.shared!.send(host: agent, userName: user.username, pduType: .getRequest, oid: oid, authenticationType: user.authentication, password: user.password)
            switch result {
            case .failure(let error):
                print("\(#function) \(user.authentication) test failure: \(error.localizedDescription)")
                XCTFail()
                return
            case .success(let variableBinding):
                guard variableBinding.oid == SnmpOid(oid)! else {
                    XCTFail()
                    return
                }
                print("\(#function) \(user.authentication) test success: \(variableBinding)")
                return
            }
        }
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
