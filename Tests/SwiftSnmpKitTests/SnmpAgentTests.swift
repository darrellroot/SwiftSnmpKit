//
//  SnmpAgentTests.swift
//  
//
//  Created by Darrell Root on 7/29/22.
//

import XCTest
import SwiftSnmpKit

/// This set of tests requires you to setup a SNMP agent in your network
/// Preferably with a SNMPv3 user per authentication type (see testUsers)
class SnmpAgentTests: XCTestCase {
    let agent = "192.168.4.120"
    let community = "public"
    struct V3parameters {
        let username: String
        let authPassword: String?
        let authentication: SnmpV3Authentication
        let privacyPassword: String?
    }
    let testUsers: [V3parameters] = [
        V3parameters(username: "ciscouser", authPassword: nil, authentication: .noAuth, privacyPassword: nil),
        V3parameters(username: "ciscoauth", authPassword: "authkey1auth", authentication: .sha1, privacyPassword: nil),
        V3parameters(username: "cisco256", authPassword: "cisco256password", authentication: .sha256, privacyPassword: nil),
        V3parameters(username: "ciscoprivuser", authPassword: "authpassword", authentication: .sha1, privacyPassword: "privpassword"),

    ]

    override func setUpWithError() throws {
        // setting short timeout for tests
        // particularly timeout tests
        SnmpSender.snmpTimeout = 1
    }

    override func tearDownWithError() throws {
        
    }

    func testV2Get1Time() async throws {
        let startTime = Date()
        try await self.testV2Get1()
        let duration = Date().timeIntervalSince(startTime)
        XCTAssert(duration < 0.2)
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
    func testv3wrongPassword() async throws {
        let oid = "1.3.6.1.2.1.1.1.0"
        let user = testUsers.filter{$0.authentication == .sha1}.first!
        let incorrectPassword = "incorrectGarbage"
        let result = await SnmpSender.shared!.send(host: agent, userName: user.username, pduType: .getRequest, oid: oid, authenticationType: user.authentication, authPassword: incorrectPassword)
        guard case let .failure(error) = result else {
            // success shouldn't happen!
            XCTFail()
            return
        }
        guard error as! SnmpError == SnmpError.snmpAuthenticationError else {
            // expected an authentication error
            XCTFail()
            return
        }
        //success! we expected an authentication error
        return
    }
    func testv3wrongUsername() async throws {
        let oid = "1.3.6.1.2.1.1.1.0"
        let user = testUsers.filter{$0.authentication == .sha1}.first!
        let incorrectUser = "incorrectGarbage"
        let result = await SnmpSender.shared!.send(host: agent, userName: incorrectUser, pduType: .getRequest, oid: oid, authenticationType: user.authentication, authPassword: user.authPassword, privPassword: user.privacyPassword)
        guard case let .failure(error) = result else {
            // success shouldn't happen!
            XCTFail()
            return
        }
        guard error as! SnmpError == SnmpError.snmpUnknownUser else {
            // expected an unknown user error
            XCTFail()
            return
        }
        //success! we expected an unknown user error
        return
    }
    func testv3sha1Time() async throws {
        let startTime = Date()
        try await self.testv3sha1()
        let duration = Date().timeIntervalSince(startTime)
        XCTAssert(duration < 0.2)
        print("duration \(duration)")
        return
    }
    func testv3sha1() async throws {
        let oid = "1.3.6.1.2.1.1.1.0"
        let user = V3parameters(username: "ciscoauth", authPassword: "authkey1auth", authentication: .sha1, privacyPassword: nil)
        let result = await SnmpSender.shared!.send(host: agent, userName: user.username, pduType: .getRequest, oid: oid, authenticationType: user.authentication, authPassword: user.authPassword)
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
            // don't return here since we need to test each user
        }
        return
    }
    func testv3get1() async throws {
        let oid = "1.3.6.1.2.1.1.1.0"

        for user in testUsers.shuffled() {
            let result = await SnmpSender.shared!.send(host: agent, userName: user.username, pduType: .getRequest, oid: oid, authenticationType: user.authentication, authPassword: user.authPassword, privPassword: user.privacyPassword)
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
                // don't return here since we need to test each user
            }
        }
    }
    func testV3AuthPriv() async throws {
        let oid = "1.3.6.1.2.1.1.1.0"

        let user = V3parameters(username: "ciscoprivuser", authPassword: "authpassword", authentication: .sha1, privacyPassword: "privpassword")
        
        let result = await SnmpSender.shared!.send(host: agent, userName: user.username, pduType: .getRequest, oid: oid, authenticationType: user.authentication, authPassword: user.authPassword, privPassword: user.privacyPassword)
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
    
    func testV2WrongIp() async throws {
        let oid = "1.3.6.1.2.1.1.1.0"
        let nonexistentHost = "172.29.212.34"
        let result = await SnmpSender.shared!.send(host: nonexistentHost, command: .getRequest, community: community, oid: oid)
        switch result {
        case .failure(let error):
            guard error as! SnmpError == SnmpError.noResponse else {
                // expected a no response  error
                XCTFail()
                return
            }
            // successfully got a no repsone error
            print("\(#function) test success: SNMPv2 timed out when requesting from a nonexistent host")
            return
        case .success(let variableBinding):
            guard variableBinding.oid == SnmpOid(oid)! else {
                XCTFail()
                return
            }
            // this SNMP request is supposed to fail!
            XCTFail()
            return
        }
    }
    
    func testV3WrongIp() async throws {
        let oid = "1.3.6.1.2.1.1.1.0"
        let nonexistentHost = "172.28.53.32"
        
        for user in testUsers.shuffled() {
            let result = await SnmpSender.shared!.send(host: nonexistentHost, userName: user.username, pduType: .getRequest, oid: oid, authenticationType: user.authentication, authPassword: user.authPassword)
            switch result {
            case .failure(let error):
                guard error as! SnmpError == SnmpError.noResponse else {
                    // expected a no response  error
                    XCTFail()
                    return
                }
                // successfully got a no repsone error
                print("\(#function) test success: SNMPv3 timed out when requesting from a nonexistent host")
                return
            case .success(let variableBinding):
                guard variableBinding.oid == SnmpOid(oid)! else {
                    XCTFail()
                    return
                }
                XCTFail("SNMP request to nonexistent host should not be successful")
                return
            }
        }
    }

    func testPerf() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
