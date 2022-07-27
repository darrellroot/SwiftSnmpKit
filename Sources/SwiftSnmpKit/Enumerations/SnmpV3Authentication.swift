//
//  File.swift
//  
//
//  Created by Darrell Root on 7/20/22.
//

import Foundation

public enum SnmpV3Authentication {
    case noAuth
    case md5
    case sha1
    case yes // for replies where we don't know the type of authentication
}
