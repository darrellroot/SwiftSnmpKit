import XCTest
@testable import SwiftSnmpKit

// Many of these tests are from https://luca.ntop.org/Teaching/Appunti/asn1.html

final class SwiftSnmpKitTests: XCTestCase {
    func testNull1() throws {
        let data = Data([0x05,0x00])
        let asnValue = try AsnValue(data: data)
        XCTAssert(asnValue == .null)
    }
    func testNull2() throws {
        let data = Data([0x05,0x81,0x00])
        let asnValue = try AsnValue(data: data)
        XCTAssert(asnValue == .null)
    }
    func testOctetStream1() throws {
        let hexStream = "04080123456789abcdef"
        let data = makeData(hexStream: hexStream)!
        let asnValue = try AsnValue(data: data)
        XCTAssert(asnValue == .octetString(Data([0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef])))
    }
    func testOctetStream2() throws {
        let hexStream = "0481080123456789abcdef"
        let data = makeData(hexStream: hexStream)!
        let asnValue = try AsnValue(data: data)
        XCTAssert(asnValue == .octetString(Data([0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef])))
    }
    func testIa51() throws {
        let data = Data([0x16,0x0d,0x74,0x65,0x73,0x74,0x31,0x40,0x72,0x73,0x61,0x2e,0x63,0x6f,0x6d])
        let asnValue = try! AsnValue(data: data)
        XCTAssert(asnValue == .ia5("test1@rsa.com"))
    }
    func testIa52() throws {
        let data = Data([0x16,0x81,0x0d,0x74,0x65,0x73,0x74,0x31,0x40,0x72,0x73,0x61,0x2e,0x63,0x6f,0x6d])
        let asnValue = try! AsnValue(data: data)
        XCTAssert(asnValue == .ia5("test1@rsa.com"))
    }
    func testInteger1() throws {
        let data = Data([0x02,0x01,0x00])
        let asnValue = try! AsnValue(data: data)
        XCTAssert(asnValue == .integer(0))
    }
    func testInteger127() throws {
        let data = Data([0x02,0x01,0x7f])
        let asnValue = try! AsnValue(data: data)
        XCTAssert(asnValue == .integer(127))
    }
    func testInteger128() throws {
        let data = Data([0x02,0x02,0x00,0x80])
        let asnValue = try! AsnValue(data: data)
        XCTAssert(asnValue == .integer(128))
    }
    func testInteger256() throws {
        let data = Data([0x02,0x02,0x01,0x00])
        let asnValue = try! AsnValue(data: data)
        XCTAssert(asnValue == .integer(256))
    }
    func testIntegerNeg128() throws {
        let data = Data([0x02,0x01,0x80])
        let asnValue = try! AsnValue(data: data)
        XCTAssert(asnValue == .integer(-128))
    }
    func testIntegerNeg129() throws {
        let data = Data([0x02,0x02,0xff,0x7f])
        let asnValue = try! AsnValue(data: data)
        XCTAssert(asnValue == .integer(-129))
    }
    func testIntegerBig1() throws {
        let asnInteger = AsnValue.integer(782105073)
        let data = asnInteger.asnData
        XCTAssert(data == Data([0x02,0x04,0x2e,0x9d,0xf9,0xf1]))
    }
    func testIntegerBig2() throws {
        let asnInteger = AsnValue.integer(1091657872)
        let data = asnInteger.asnData
        XCTAssert(data == Data([0x02,0x04,0x41,0x11,0x60,0x90]))
    }
    /*func testIntegerBigNegative() throws {
        let asnInteger = AsnValue.integer(-1446203843)
        let data = asnInteger.asnData
        XCTAssert(data == Data([0x02,0x04,0x41,0x11,0x60,0x90]))
    }*/
    func testOid1() throws {
        let data = Data([0x06,0x06,0x2a,0x86,0x48,0x86,0xf7,0x0d])
        let asnValue = try! AsnValue(data: data)
        let correctOID = SnmpOid(nodes: [1,2,840,113549])!
        let incorrectOID = SnmpOid(".1.2.840.113550")!
        XCTAssert(asnValue == .oid(correctOID))
        XCTAssert(asnValue != .oid(incorrectOID))
    }
    func testSequence1() throws {
        let data = Data([0x30,0x02,0x05,0x00])
        let asnValue = try! AsnValue(data: data)
        XCTAssert(asnValue == AsnValue.sequence([AsnValue.null]))
    }
    func testSequence2() throws {
        let data = Data([0x30,0x04,0x05,0x00,0x05,0x00])
        let asnValue = try! AsnValue(data: data)
        XCTAssert(asnValue == AsnValue.sequence([AsnValue.null,AsnValue.null]))
    }
    
    func testSnmpResponse1() throws {
        /*Simple Network Management Protocol
            version: v2c (1)
            community: public
            data: get-response (2)
                get-response
                    request-id: 782105073
                    error-status: noError (0)
                    error-index: 0
                    variable-bindings: 1 item
                        1.3.6.1.2.1.1.1.0: "SG250-08 8-Port Gigabit Smart Switch"
                            Object Name: 1.3.6.1.2.1.1.1.0 (iso.3.6.1.2.1.1.1.0)
                            Value (OctetString): "SG250-08 8-Port Gigabit Smart Switch"
                                Variable-binding-string: SG250-08 8-Port Gigabit Smart Switch*/
        let hexStream  = "304d02010104067075626c6963a24002042e9df9f10201000201003032303006082b06010201010100042453473235302d303820382d506f7274204769676162697420536d61727420537769746368"
        guard let data = makeData(hexStream: hexStream) else {
            XCTFail()
            return
        }
        let asnValue = try! AsnValue(data: data)
        
        guard case .sequence(let sequence) = asnValue else {
            XCTFail()
            return
        }
        XCTAssert(sequence[0] == .integer(1))
        XCTAssert(sequence[1] == .octetString(Data([0x70,0x75,0x62,0x6c,0x69,0x63])))
        guard case .snmpResponse(let response) = sequence[2] else {
            XCTFail()
            return
        }
        XCTAssert(response.requestId == 782105073)
        XCTAssert(response.errorStatus == 0)
        XCTAssert(response.errorIndex == 0)
    }
    func testSnmpPdu1() throws {
        /*Simple Network Management Protocol
            version: v2c (1)
            community: public
            data: get-response (2)
                get-response
                    request-id: 782105073
                    error-status: noError (0)
                    error-index: 0
                    variable-bindings: 1 item
                        1.3.6.1.2.1.1.1.0: "SG250-08 8-Port Gigabit Smart Switch"
                            Object Name: 1.3.6.1.2.1.1.1.0 (iso.3.6.1.2.1.1.1.0)
                            Value (OctetString): "SG250-08 8-Port Gigabit Smart Switch"
                                Variable-binding-string: SG250-08 8-Port Gigabit Smart Switch*/
        let hexStream  = "304d02010104067075626c6963a24002042e9df9f10201000201003032303006082b06010201010100042453473235302d303820382d506f7274204769676162697420536d61727420537769746368"
        guard let data = makeData(hexStream: hexStream) else {
            XCTFail()
            return
        }
        guard let snmpPdu = SnmpMessage(data: data) else {
            XCTFail()
            return
        }
        XCTAssert(snmpPdu.version == .v2c)
        XCTAssert(snmpPdu.community == "public")
        XCTAssert(snmpPdu.command == .getResponse)
        XCTAssert(snmpPdu.requestId == 782105073)
        XCTAssert(snmpPdu.errorStatus == 0)
        XCTAssert(snmpPdu.errorIndex == 0)
        XCTAssert(snmpPdu.variableBindings.count == 1)
        //print(snmpPdu.variableBindings)
    }
    func testPowerOf128() {
        XCTAssert(SnmpUtils.powerOf128(0) == 1)
        XCTAssert(SnmpUtils.powerOf128(1) == 128)
        XCTAssert(SnmpUtils.powerOf128(2) == 128 * 128)
        XCTAssert(SnmpUtils.powerOf128(3) == 128 * 128 * 128)
    }
    func testPowerOf256() {
        XCTAssert(SnmpUtils.powerOf256(0) == 1)
        XCTAssert(SnmpUtils.powerOf256(1) == 256)
        XCTAssert(SnmpUtils.powerOf256(2) == 256 * 256)
        XCTAssert(SnmpUtils.powerOf256(3) == 256 * 256 * 256)
    }
    func testIntegerData0() {
        let value = AsnValue.integer(0)
        let data = value.asnData
        XCTAssert(data == Data([2,1,0]))
    }
    func testIntegerData127() {
        let value = AsnValue.integer(127)
        let data = value.asnData
        XCTAssert(data == Data([2,1,0x7f]))
    }
    func testIntegerData128() {
        let value = AsnValue.integer(128)
        let data = value.asnData
        XCTAssert(data == Data([2,2,0,0x80]))
    }
    func testIntegerData256() {
        let value = AsnValue.integer(256)
        let data = value.asnData
        XCTAssert(data == Data([2,2,1,0]))
    }
    func testIntegerDataNeg128() {
        let value = AsnValue.integer(-128)
        let data = value.asnData
        XCTAssert(data == Data([2,1,0x80]))
    }
    func testIntegerDataNeg129() {
        let value = AsnValue.integer(-129)
        let data = value.asnData
        XCTAssert(data == Data([2,2,0xff,0x7f]))
    }
    func testBase128ToData() {
        let data = AsnValue.base128ToData(113549)
        XCTAssert(data == Data([0x86,0xf7,0x0d]))
    }
    func testOidData1() {
        let snmpOid = SnmpOid(nodes: [1,2,840,113549])!
        XCTAssert(snmpOid.nodes == [1,2,840,113549])
        let value = AsnValue.oid(snmpOid)
        let data = value.asnData
        XCTAssert(data == Data([6,6,0x2a,0x86,0x48,0x86,0xf7,0x0d]))
    }
    func testOidData2() {
        let snmpOid = SnmpOid(nodes: [1,2,3])!
        XCTAssert(snmpOid.nodes == [1,2,3])
        let value = AsnValue.oid(snmpOid)
        let data = value.asnData
        XCTAssert(data == Data([6,2,0x2a,3]))
    }
    func testOidData3() {
        let snmpOid = SnmpOid(nodes: [1,2,128])!
        XCTAssert(snmpOid.nodes == [1,2,128])
        let value = AsnValue.oid(snmpOid)
        let data = value.asnData
        XCTAssert(data == Data([6,3,0x2a,129,0]))
    }
    func testOidData4() {
        let snmpOid = SnmpOid(nodes: [1,2,16384])!
        XCTAssert(snmpOid.nodes == [1,2,16384])
        let value = AsnValue.oid(snmpOid)
        let data = value.asnData
        XCTAssert(data == Data([6,4,0x2a,129,128,0]))
    }
    func testOidData5() {
        let snmpOid = SnmpOid(nodes: [1,2,2097152])!
        XCTAssert(snmpOid.nodes == [1,2,2097152])
        let value = AsnValue.oid(snmpOid)
        let data = value.asnData
        XCTAssert(data == Data([6,5,0x2a,129,128,128,0]))
    }
    func testOidData6() {
        let oid = "1.3.6.1.2.1.1.1.0"
        let snmpOid = SnmpOid(oid)!
        let data = snmpOid.asnData
        XCTAssert(data == Data([0x06,0x08,0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00]))
    }
    func testOctetData1() {
        let octetString = AsnValue.octetString(Data([0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef]))
        let data = octetString.asnData
        XCTAssert(data == Data([0x04,0x08,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef]))
    }
    func testIa5Data1() {
        let string = "test1@rsa.com"
        let value = AsnValue.ia5(string)
        let data = value.asnData
        XCTAssertEqual(data, Data([0x16,0x0d,0x74,0x65,0x73,0x74,0x31,0x40,0x72,0x73,0x61,0x2e,0x63,0x6f,0x6d]))
    }
    func testVariableBindingData1() throws {
        let string = "SG250-08 8-Port Gigabit Smart Switch"
        let oid = "1.3.6.1.2.1.1.1.0"
        let snmpOid = SnmpOid(oid)!
        var variableBinding = SnmpVariableBinding(oid: snmpOid)
        variableBinding.value = AsnValue(octetString: string)
        let variableBindingData = variableBinding.asnData
        let expectedData = makeData(hexStream: "303006082b06010201010100042453473235302d303820382d506f7274204769676162697420536d61727420537769746368")
        XCTAssert(variableBindingData == expectedData)
    }
    func testVariableBindingData2() throws {
        let oid = "1.3.6.1.2.1"
        let snmpOid = SnmpOid(oid)!
        let variableBinding = SnmpVariableBinding(oid: snmpOid)
        let variableBindingData = variableBinding.asnData
        let expectedData = makeData(hexStream: "300906052b060102010500")
        XCTAssert(variableBindingData == expectedData)
    }
    func testVariableBindingsData1() throws {
        let oid = "1.3.6.1.2.1"
        let snmpOid = SnmpOid(oid)!
        let variableBinding = SnmpVariableBinding(oid: snmpOid)
        let variableBindingsData = [variableBinding].asnData
        let expectedData = makeData(hexStream: "300b300906052b060102010500")
        XCTAssert(variableBindingsData == expectedData)
    }
    func testNoSuchOid1() throws {
        let data = makeData(hexStream: "302902010104067075626c6963a21c02040eb1eaef020100020100300e300c06082b090102010101008000")!
        let snmpMessage = SnmpMessage(data: data)!
        let variableBinding = snmpMessage.variableBindings.first!
        XCTAssert(variableBinding.value == .noSuchObject)
    }
    func testSnmpResponseData() throws {
        var variableBinding = SnmpVariableBinding(oid: SnmpOid("1.3.6.1.2.1.1.1.0")!)
        let octetString = AsnValue(octetString: "SG250-08 8-Port Gigabit Smart Switch")
        variableBinding.value = octetString
        var snmpPdu = SnmpPdu(type: .getResponse, requestId: 782105073, variableBindings: [variableBinding])
        let snmpResponse = AsnValue.snmpResponse(snmpPdu)
        let responseData = snmpResponse.asnData
        let hexstream = "a24002042e9df9f10201000201003032303006082b06010201010100042453473235302d303820382d506f7274204769676162697420536d61727420537769746368"
        let expectedData = makeData(hexStream: hexstream)
        XCTAssert(responseData == expectedData)
    }
    // simply tests that we can create a snmp session
    /*func testSession1() throws {
        let session = SnmpSession(host: "", version: .v2c, community: "public")
        XCTAssert(session != nil)
    }*/
    func testSendSnmp2() throws {
        let snmpMessage = SnmpMessage(community: "public", command: .getRequest, oid: SnmpOid("1.3.6.1.2.1.1.1.0")!)
        let data = snmpMessage.asnData
        try! SnmpSender.shared?.sendData(host: "192.168.4.120",port: 161, data: data)
        sleep(2)
    }
    /*func testSendSnmp() throws {
        guard let snmpSession = SnmpSession(host: "", version: .v2c, community: "public") else {
            XCTFail()
            return
        }
        guard let oid = SnmpOid("1.3.6.1.2.1.1.1.0") else {
            XCTFail()
            return
        }
        let agent = "192.168.4.120"
        let community = "public"
        let snmpMessage = SnmpMessage(version: .v2c, community: community, command: .getNextRequest, oid: oid)
        sleep(1)
        let data = snmpMessage.asnData
        do {
            try snmpSession.sendData(host: agent, data: data)
        } catch {
            print("\(error.localizedDescription)")
            XCTFail()
        }
        sleep(2)
        print("done with snmp send test, check tcpdump")
    }*/
    
}


extension SwiftSnmpKitTests {
    func makeData(hexStream: String) -> Data? {
        var total = 0
        var data = Data(capacity: (hexStream.count / 2 + 1))
        for (count,char) in hexStream.enumerated() {
            guard let charValue = Int(String(char), radix: 16) else {
                SnmpError.log("makeData: invalid char \(char) at position \(count)")
                return nil
            }
            if count % 2 == 0 {
                total = charValue * 16
            } else {
                total = total + charValue
                data.append(UInt8(total))
            }
        }
        return data
    }
}
