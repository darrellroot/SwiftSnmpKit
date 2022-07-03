//
//  File.swift
//  
//
//  Created by Darrell Root on 7/1/22.
//

import Foundation
public enum SnmpPduType: Int, Equatable, CustomStringConvertible {
    case getNextRequest = 1
    case getResponse = 2
    
    public var description: String {
        switch self {
        case .getNextRequest:
            return "Get-Next-Request"
        case .getResponse:
            return "Get-Response"
        }
    }
}
