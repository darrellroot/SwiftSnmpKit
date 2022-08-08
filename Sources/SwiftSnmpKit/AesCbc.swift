//
//  File.swift
//  
//
//  Created by Darrell Root on 8/5/22.

import Foundation
import CryptoSwift

enum AesCbcError: Error {
    case badIvSize
    case badKeySize
    case badDataSize
}
struct AesCbc {
    static func xor(_ first: ArraySlice<UInt8>, _ second: [UInt8]) throws -> [UInt8] {
        guard first.count == second.count else {
            throw AesCbcError.badDataSize
        }
        var result = [UInt8](Data(count: first.count))
        for byte in 0..<first.count {
            result[byte] = first[first.startIndex + byte] ^ second[second.startIndex + byte]
        }
        return result
    }
    static func encrypt(plaintext: Data, iv: Data, key: Data) throws -> Data {
        guard iv.count == 16 else {
            throw AesCbcError.badIvSize
        }
        guard key.count == 16 else {
            throw AesCbcError.badKeySize
        }
        guard plaintext.count > 0 else {
            return Data()
        }
        let paddingNeeded: Int
        let finalBlockLength: Int
        if plaintext.count % 16 == 0 {
            paddingNeeded = 0
            finalBlockLength = 16
        } else {
            finalBlockLength = plaintext.count % 16
            paddingNeeded = 16 - finalBlockLength
        }
        let paddedPlaintext = [UInt8](plaintext + Data(count: paddingNeeded))
        let blocks = paddedPlaintext.count / 16 - 1
        var result = Data(capacity: plaintext.count)
        var inputBlock = [UInt8](iv)
        var outputBlock = [UInt8](Data(count: 16))
        // will not fail since key is guaranteed 16 octets
        let aes = try AES(key: [UInt8](key), blockMode: ECB(), padding: .noPadding)
        for block in 0..<blocks {
            // will not fail as long as everything is length 16
            outputBlock = try aes.encrypt(inputBlock)
            inputBlock = outputBlock
            if block == blocks-1 {
                // last block is special
            } else {
                let ciphertextBlock = try! xor(paddedPlaintext[(16*block)..<16*(block+1)],outputBlock)
                result[(16*block)..<16*(block+1)] = Data(ciphertextBlock)
            }
        }
        return Data()
    }
}
