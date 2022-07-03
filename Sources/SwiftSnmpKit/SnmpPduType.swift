//
//  File.swift
//  
//
//  Created by Darrell Root on 7/1/22.
//

import Foundation
public enum SnmpPduType: Int, Equatable {
    case getNextRequest = 1
    case getResponse = 2
}
