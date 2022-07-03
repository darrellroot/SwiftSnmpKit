import XCTest
@testable import SwiftSnmpKit

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
    func testOid1() throws {
        let data = Data([0x06,0x06,0x2a,0x86,0x48,0x86,0xf7,0x0d])
        let asnValue = try! AsnValue(data: data)
        XCTAssert(asnValue == .oid([1,2,840,113549]))
        XCTAssert(asnValue != .oid([1,2,840,113550]))
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
        XCTAssert(snmpPdu.version == 1)
        XCTAssert(snmpPdu.community == "public")
        XCTAssert(snmpPdu.command == .getResponse)
        XCTAssert(snmpPdu.requestId == 782105073)
        XCTAssert(snmpPdu.errorStatus == 0)
        XCTAssert(snmpPdu.errorIndex == 0)
        XCTAssert(snmpPdu.variableBindings.count == 1)
        print(snmpPdu.variableBindings)
        
    }
    

    func makeData(hexStream: String) -> Data? {
        var total = 0
        var data = Data(capacity: (hexStream.count / 2 + 1))
        for (count,char) in hexStream.enumerated() {
            guard let charValue = Int(String(char), radix: 16) else {
                AsnError.log("makeData: invalid char \(char) at position \(count)")
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
