# ``SwiftSnmpKit``

A Swift Package for making SNMP (Simple Network Management Protocol) requests to network devices.

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
