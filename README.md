# ``SwiftSnmpKit``

A Swift Package for making SNMP (Simple Network Management Protocol) requests to network devices.

## Features

SwiftSnmpKit supports the following SNMP versions:

1. SNMPv2c (with community-based authentication)
2. SNMPv3 no authentication no privacy
3. SNMPv3 authentication no privacy
4. SNMPv3 authentication and privacy

Only SNMP queries to UDP port 161 are supported.  SNMP traps or informs to UDP port 162 are not supported.  TCP transport is not supported.

The following SNMP query types are supported:

1. SNMP Get
2. SNMP GetNext

The following SNMP reply types are supported:

1. SNMP Response
2. SNMP Report

SNMP EngineIDs, Engine Boots, and Engine Times will be reported by the SnmpSender singleton and used for future queries.

## Overview

1. Use Swift Package Manager to import SwiftSnmpKit
2. Include SwiftSnmpKit in your "Link Binary with Libraries"
3. Add `import SwiftSnmpKit` at the top of your source file
4. Initialize the SnmpSender singleton using `guard let snmpSender = SnmpSender.shared else...`
5. Inside an async function, send and await for a SNMP request using `await snmpSender.send()`
6. Switch on the result to get a SNMP variable binding (success) or error (failure).

### Swift Package Manager

You can use [Swift Package Manager](https://swift.org/package-manager/) and specify dependency in `Package.swift` by adding this:

```swift
.package(url: "https://github.com/darrellroot/SwiftSnmpKit.git", .upToNextMajor(from: "0.1.6"))
```
### Initialize the SNMP Sender singleton
```
guard let snmpSender = SnmpSender.shared else {
    fatalError("Snmp Sender not inialized")
}
```
### Send a SNMP request and wait for reply (SNMPv2c example)
```
let result = await snmpSender.send(host: agent,
    command: .getRequest, community: community,
    oid: "1.3.6.1.2.1.1.1.0")
```
### Send a SNMP request and wait for reply (SNMPv3 example)
```
let getNextResult = await snmpSender.send(host: agent,
    userName: "ciscoprivuser", pduType: .getNextRequest,
    oid: "1.3.6.1.2", authenticationType: .sha1,
    authPassword: "authpassword",
    privPassword: "privpassword")
```
authPassword and privPassword parameters are optional.

SNMPv2c requests will be attempted only once. Your code needs to retransmit in the event of packet loss.

SNMPv3 requests will be attempted up to three times.  This allows SNMP reports to populate the EngineID, EngineBoots, and EngineTime fields.

### Switch on result

```
switch getNextResult {
case .failure(let error):
    consecutiveNextFailures += 1
    print("SNMP Error: \(error.localizedDescription)")
case .success(let variableBinding):
    print(variableBinding)
    if variableBinding.value == AsnValue.endOfMibView {
        done = true
    }
    if variableBinding.value == AsnValue.noSuchObject {
        consecutiveNextFailures += 1
    } else {
        consecutiveNextFailures = 0
    }
    nextOid = variableBinding.oid
}
```

### Sample Project

A sample project with command-line SNMP tools is at https://github.com/darrellroot/SwiftSnmpTools

