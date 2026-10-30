# QVehicle

QVehicle is a live production post quantum vehicle registry tool on the Quantova network. It proves the registration, inspection, transfer and deregistration of vehicles, vessels and aircraft, and it lets any third party confirm that history without trusting the party that created it.

Only a salted cryptographic commitment is written to the chain. Vehicle identities and keeper details stay private on the systems of the party that holds them.

## What it records

1. register, an authority records a vehicle with its identification number, class, make, model, year, jurisdiction and first registered keeper.
2. inspect, an inspector records the outcome and odometer reading of a roadworthiness inspection.
3. transfer, the registered keeper transfers the vehicle to another party.
4. deregister, an authority removes the vehicle from the register.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names.

## Install

```
npm install @quantovainc/qvehicle
```

## License

Apache-2.0 OR MIT
