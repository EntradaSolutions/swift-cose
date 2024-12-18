import Foundation
import CryptoKit
import K1
import CryptoSwift


public func derivePublicNumbersCompact(from d: Data, curve: CurveType) -> (Data, Data?) {
    
    var x: Data?
    var y: Data?
    
    switch curve {
        case .SECP256K1:
            let publicKey: K1.KeyAgreement.PublicKey = derivePublicKeyCompact(from: d, curve: curve)
            x = publicKey.x963Representation.subdata(in: 1..<33)
            y = publicKey.x963Representation.subdata(in: 33..<65)
        case .SECP256R1:
            let publicKey: P256.KeyAgreement.PublicKey = derivePublicKeyCompact(from: d, curve: curve)
            x = publicKey.x963Representation.subdata(in: 1..<33)
            y = publicKey.x963Representation.subdata(in: 33..<65)
        case .SECP384R1:
            let publicKey: P384.KeyAgreement.PublicKey = derivePublicKeyCompact(from: d, curve: curve)
            x = publicKey.x963Representation.subdata(in: 1..<49)
            y = publicKey.x963Representation.subdata(in: 49..<97)
        case .SECP521R1:
            let publicKey: P521.KeyAgreement.PublicKey = derivePublicKeyCompact(from: d, curve: curve)
            x = publicKey.x963Representation.subdata(in: 1..<65)
            y = publicKey.x963Representation.subdata(in: 65..<129)
        case .ED25519:
            let publicKey: Curve25519.Signing.PublicKey = derivePublicKeyCompact(from: d, curve: curve)
            x = publicKey.rawRepresentation
        case .ED448:
            let publicKey: Curve448.Signing.PublicKey = derivePublicKeyCompact(from: d, curve: curve)
            x = publicKey.rawRepresentation
        case .X25519:
            let publicKey: Curve25519.KeyAgreement.PublicKey = derivePublicKeyCompact(from: d, curve: curve)
            x = publicKey.rawRepresentation
        case .X448:
            let publicKey: Curve448.KeyAgreement.PublicKey = derivePublicKeyCompact(from: d, curve: curve)
            x = publicKey.rawRepresentation
    }
    
    return (x!, y)
}

public func derivePublicNumbers(from d: Data, curve: CurveType) -> (Data, Data?) {
    
    var x: Data?
    var y: Data?
    
    switch curve {
        case .SECP256K1:
            let privateKey: K1.KeyAgreement.PrivateKey = derivePrivateKey(from: d, curve: curve)
            x = privateKey.publicKey.x963Representation.subdata(in: 1..<33)
            y = privateKey.publicKey.x963Representation.subdata(in: 33..<65)
        case .SECP256R1:
            let privateKey: P256.KeyAgreement.PrivateKey = derivePrivateKey(from: d, curve: curve)
            x = privateKey.publicKey.x963Representation.subdata(in: 1..<33)
            y = privateKey.publicKey.x963Representation.subdata(in: 33..<65)
        case .SECP384R1:
            let privateKey: P384.KeyAgreement.PrivateKey = derivePrivateKey(from: d, curve: curve)
            x = privateKey.publicKey.x963Representation.subdata(in: 1..<49)
            y = privateKey.publicKey.x963Representation.subdata(in: 49..<97)
        case .SECP521R1:
            let privateKey: P521.KeyAgreement.PrivateKey = derivePrivateKey(from: d, curve: curve)
            x = privateKey.publicKey.x963Representation.subdata(in: 1..<65)
            y = privateKey.publicKey.x963Representation.subdata(in: 65..<129)
        case .ED25519:
            let privateKey: Curve25519.Signing.PrivateKey = derivePrivateKey(from: d, curve: curve)
            x = privateKey.publicKey.rawRepresentation
        case .ED448:
            let privateKey: Curve448.Signing.PrivateKey = derivePrivateKey(from: d, curve: curve)
            x = privateKey.publicKey.rawRepresentation
        case .X25519:
            let privateKey: Curve25519.KeyAgreement.PrivateKey = derivePrivateKey(from: d, curve: curve)
            x = privateKey.publicKey.rawRepresentation
        case .X448:
            let privateKey: Curve448.KeyAgreement.PrivateKey = derivePrivateKey(from: d, curve: curve)
            x = privateKey.publicKey.rawRepresentation
    }
    
    return (x!, y)
}


public func derivePrivateKey<T>(from key: Data, curve: CurveType) -> T {
    switch curve {
        case .SECP256K1:
            return try! K1.KeyAgreement.PrivateKey(rawRepresentation: key) as! T
        case .SECP256R1:
            return try! P256.KeyAgreement.PrivateKey(rawRepresentation: key) as! T
        case .SECP384R1:
            return try! P384.KeyAgreement.PrivateKey(rawRepresentation: key) as! T
        case .SECP521R1:
            return try! P521.KeyAgreement.PrivateKey(rawRepresentation: key) as! T
        case .ED25519:
            return try! Curve25519.Signing.PrivateKey(rawRepresentation: key) as! T
        case .ED448:
            return try! Curve448.Signing.PrivateKey(rawRepresentation: key) as! T
        case .X25519:
            return try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: key) as! T
        case .X448:
            return try! Curve448.KeyAgreement.PrivateKey(rawRepresentation: key) as! T
    }
}


public func derivePublicKeyCompact<T>(from key: Data, curve: CurveType) -> T {
    switch curve {
        case .SECP256K1:
            return try! K1.KeyAgreement.PublicKey(compressedRepresentation: key) as! T
        case .SECP256R1:
            return try! P256.KeyAgreement.PublicKey(compressedRepresentation: key) as! T
        case .SECP384R1:
            return try! P384.KeyAgreement.PublicKey(compressedRepresentation: key) as! T
        case .SECP521R1:
            return try! P521.KeyAgreement.PublicKey(compressedRepresentation: key) as! T
        case .ED25519:
            return try! Curve25519.Signing.PublicKey(rawRepresentation: key) as! T
        case .ED448:
            return try! Curve448.Signing.PublicKey(rawRepresentation: key) as! T
        case .X25519:
            return try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: key) as! T
        case .X448:
            return try! Curve448.KeyAgreement.PublicKey(rawRepresentation: key) as! T
    }
}


public func generatePrivateKey<T>(curve: CurveType) -> T {
    switch curve {
        case .SECP256K1:
            return K1.KeyAgreement.PrivateKey() as! T
        case .SECP256R1:
            return P256.KeyAgreement.PrivateKey() as! T
        case .SECP384R1:
            return P384.KeyAgreement.PrivateKey() as! T
        case .SECP521R1:
            return P521.KeyAgreement.PrivateKey() as! T
        case .ED25519:
            return Curve25519.Signing.PrivateKey() as! T
        case .ED448:
            return Curve448.Signing.PrivateKey() as! T
        case .X25519:
            return Curve25519.KeyAgreement.PrivateKey() as! T
        case .X448:
            return Curve448.KeyAgreement.PrivateKey() as! T
    }
}
