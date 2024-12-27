import Testing
import Foundation
import CryptoKit
import K1
import CryptoSwift
import SwiftCurve448
@testable import SwiftCose

struct CryptoTests {
    
    // MARK: - Key Generation Tests
    
    @Test func testSECP256K1() async throws {
        let privateKeyAgreementKey: K1.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: .SECP256K1)
        let privateSigningKey: K1.ECDSA.PrivateKey = try generateSigningPrivateKey(curve: .SECP256K1)
        
        let publicKeyAgreementKeyCompact: K1.KeyAgreement.PublicKey = try deriveKeyAgreementPublicKeyCompact(
            from: privateKeyAgreementKey.publicKey.compressedRepresentation,
            curve: .SECP256K1
        ) as K1.KeyAgreement.PublicKey
        let publicSigningKeyCompact: K1.ECDSA.PublicKey = try deriveSigningPublicKeyCompact(
            from: privateSigningKey.publicKey.compressedRepresentation,
            curve: .SECP256K1
        )
        
        let derivedPrivateKeyAgreementKey: K1.KeyAgreement.PrivateKey = try deriveKeyAgreementPrivateKey(
            from: privateKeyAgreementKey.rawRepresentation,
            curve: .SECP256K1
        )
        let derivedPrivateKeySigningKey: K1.ECDSA.PrivateKey = try deriveSigningPrivateKey(
            from: privateSigningKey.rawRepresentation,
            curve: .SECP256K1
        )
        
        let (curve1, x1, y1, d1) = try deriveNumbers(from: privateKeyAgreementKey)
        let (curve2, x2, y2, d2) = try deriveNumbers(from: privateKeyAgreementKey.publicKey)
        
        let derivedPublicKeyAgreementKey: K1.KeyAgreement.PublicKey = try derivePublicKeyFromNumbers(
            curve: curve1,
            x: x1,
            y: y1!
        )
            
        
        let (xKA, yKA) = try deriveKeyAgreementPublicNumbers(
            from: privateKeyAgreementKey.rawRepresentation,
            curve: .SECP256K1
        )
        let (xS, yS) = try deriveSigningPublicNumbers(
            from: privateSigningKey.rawRepresentation,
            curve: .SECP256K1
        )
        
        let (xKAc, yKAc) = try deriveKeyAgreementPublicNumbersCompact(
            from: privateKeyAgreementKey.publicKey.compressedRepresentation,
            curve: .SECP256K1
        )
        let (xSc, ySc) = try deriveSigningPublicNumbersCompact(
            from: privateSigningKey.publicKey.compressedRepresentation,
            curve: .SECP256K1
        )
        
        #expect(privateKeyAgreementKey.rawRepresentation.count == 32)
        #expect(privateSigningKey.rawRepresentation.count == 32)
        
        #expect(publicKeyAgreementKeyCompact.rawRepresentation == derivedPublicKeyAgreementKey.rawRepresentation)
        
        #expect(publicKeyAgreementKeyCompact.rawRepresentation == privateKeyAgreementKey.publicKey.rawRepresentation)
        #expect(publicSigningKeyCompact.rawRepresentation.count == privateSigningKey.publicKey.rawRepresentation.count)
        
        #expect(privateKeyAgreementKey.rawRepresentation == derivedPrivateKeyAgreementKey.rawRepresentation)
        #expect(privateSigningKey.rawRepresentation == derivedPrivateKeySigningKey.rawRepresentation)
        
        #expect(xKA == xKAc)
        #expect(yKA == yKAc)
        #expect(xS == xSc)
        #expect(yS == ySc)
        
        #expect(curve1 == .SECP256K1)
        #expect(curve2 == .SECP256K1)
        #expect(x1 == xKAc)
        #expect(y1 == yKAc)
        #expect(d1 == privateKeyAgreementKey.rawRepresentation)
        #expect(x2 == xKAc)
        #expect(y2 == yKAc)
        #expect(d2 == nil)
    }
    
    @Test func testSECP256R1() async throws {
        let privateKeyAgreementKey: P256.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: .SECP256R1)
        let privateSigningKey: P256.Signing.PrivateKey = try generateSigningPrivateKey(
            curve: .SECP256R1
        )
        
        let publicKeyAgreementKeyCompact: P256.KeyAgreement.PublicKey = try deriveKeyAgreementPublicKeyCompact(
            from: privateKeyAgreementKey.publicKey.compressedRepresentation,
            curve: .SECP256R1
        )
        let publicSigningKeyCompact: P256.Signing.PublicKey = try deriveSigningPublicKeyCompact(
            from: privateSigningKey.publicKey.compressedRepresentation,
            curve: .SECP256R1
        )
        
        let derivedPrivateKeyAgreementKey: P256.KeyAgreement.PrivateKey = try deriveKeyAgreementPrivateKey(
            from: privateKeyAgreementKey.rawRepresentation,
            curve: .SECP256R1
        )
        let derivedPrivateKeySigningKey: P256.Signing.PrivateKey = try deriveSigningPrivateKey(
            from: privateSigningKey.rawRepresentation,
            curve: .SECP256R1
        )
        
        let (curve1, x1, y1, d1) = try deriveNumbers(from: privateKeyAgreementKey)
        let (curve2, x2, y2, d2) = try deriveNumbers(from: privateKeyAgreementKey.publicKey)
        
        let derivedPublicKeyAgreementKey: P256.KeyAgreement.PublicKey = try derivePublicKeyFromNumbers(
            curve: curve1,
            x: x1,
            y: y1!
        )
        
        let (xKA, yKA) = try deriveKeyAgreementPublicNumbers(
            from: privateKeyAgreementKey.rawRepresentation,
            curve: .SECP256R1
        )
        let (xS, yS) = try deriveSigningPublicNumbers(
            from: privateSigningKey.rawRepresentation,
            curve: .SECP256R1
        )
        
        let (xKAc, yKAc) = try deriveKeyAgreementPublicNumbersCompact(
            from: privateKeyAgreementKey.publicKey.compressedRepresentation,
            curve: .SECP256R1
        )
        let (xSc, ySc) = try deriveSigningPublicNumbersCompact(
            from: privateSigningKey.publicKey.compressedRepresentation,
            curve: .SECP256R1
        )
        
        #expect(privateKeyAgreementKey.rawRepresentation.count == 32)
        #expect(privateSigningKey.rawRepresentation.count == 32)
        
        #expect(publicKeyAgreementKeyCompact.rawRepresentation == derivedPublicKeyAgreementKey.rawRepresentation)
        
        #expect(publicKeyAgreementKeyCompact.rawRepresentation == privateKeyAgreementKey.publicKey.rawRepresentation)
        #expect(publicSigningKeyCompact.rawRepresentation.count == privateSigningKey.publicKey.rawRepresentation.count)
        
        #expect(privateKeyAgreementKey.rawRepresentation == derivedPrivateKeyAgreementKey.rawRepresentation)
        #expect(privateSigningKey.rawRepresentation == derivedPrivateKeySigningKey.rawRepresentation)
        
        #expect(xKA == xKAc)
        #expect(yKA == yKAc)
        #expect(xS == xSc)
        #expect(yS == ySc)
        
        #expect(curve1 == .SECP256R1)
        #expect(curve2 == .SECP256R1)
        #expect(x1 == xKAc)
        #expect(y1 == yKAc)
        #expect(d1 == privateKeyAgreementKey.rawRepresentation)
        #expect(x2 == xKAc)
        #expect(y2 == yKAc)
        #expect(d2 == nil)
    }
    
    @Test func testSECP384R1() async throws {
        let privateKeyAgreementKey: P384.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: .SECP384R1)
        let privateSigningKey: P384.Signing.PrivateKey = try generateSigningPrivateKey(
            curve: .SECP384R1
        )
        
        let publicKeyAgreementKeyCompact: P384.KeyAgreement.PublicKey = try deriveKeyAgreementPublicKeyCompact(
            from: privateKeyAgreementKey.publicKey.compressedRepresentation,
            curve: .SECP384R1
        )
        let publicSigningKeyCompact: P384.Signing.PublicKey = try deriveSigningPublicKeyCompact(
            from: privateSigningKey.publicKey.compressedRepresentation,
            curve: .SECP384R1
        )
        
        let derivedPrivateKeyAgreementKey: P384.KeyAgreement.PrivateKey = try deriveKeyAgreementPrivateKey(
            from: privateKeyAgreementKey.rawRepresentation,
            curve: .SECP384R1
        )
        let derivedPrivateKeySigningKey: P384.Signing.PrivateKey = try deriveSigningPrivateKey(
            from: privateSigningKey.rawRepresentation,
            curve: .SECP384R1
        )
        
        let (curve1, x1, y1, d1) = try deriveNumbers(from: privateKeyAgreementKey)
        let (curve2, x2, y2, d2) = try deriveNumbers(from: privateKeyAgreementKey.publicKey)
        
        let derivedPublicKeyAgreementKey: P384.KeyAgreement.PublicKey = try derivePublicKeyFromNumbers(
            curve: curve1,
            x: x1,
            y: y1!
        )
        
        let (xKA, yKA) = try deriveKeyAgreementPublicNumbers(
            from: privateKeyAgreementKey.rawRepresentation,
            curve: .SECP384R1
        )
        let (xS, yS) = try deriveSigningPublicNumbers(
            from: privateSigningKey.rawRepresentation,
            curve: .SECP384R1
        )
        
        let (xKAc, yKAc) = try deriveKeyAgreementPublicNumbersCompact(
            from: privateKeyAgreementKey.publicKey.compressedRepresentation,
            curve: .SECP384R1
        )
        let (xSc, ySc) = try deriveSigningPublicNumbersCompact(
            from: privateSigningKey.publicKey.compressedRepresentation,
            curve: .SECP384R1
        )
        
        #expect(privateKeyAgreementKey.rawRepresentation.count == 48)
        #expect(privateSigningKey.rawRepresentation.count == 48)
        
        #expect(publicKeyAgreementKeyCompact.rawRepresentation == derivedPublicKeyAgreementKey.rawRepresentation)
        
        #expect(publicKeyAgreementKeyCompact.rawRepresentation == privateKeyAgreementKey.publicKey.rawRepresentation)
        #expect(publicSigningKeyCompact.rawRepresentation.count == privateSigningKey.publicKey.rawRepresentation.count)
        
        #expect(privateKeyAgreementKey.rawRepresentation == derivedPrivateKeyAgreementKey.rawRepresentation)
        #expect(privateSigningKey.rawRepresentation == derivedPrivateKeySigningKey.rawRepresentation)
        
        #expect(xKA == xKAc)
        #expect(yKA == yKAc)
        #expect(xS == xSc)
        #expect(yS == ySc)
        
        #expect(curve1 == .SECP384R1)
        #expect(curve2 == .SECP384R1)
        #expect(x1 == xKAc)
        #expect(y1 == yKAc)
        #expect(d1 == privateKeyAgreementKey.rawRepresentation)
        #expect(x2 == xKAc)
        #expect(y2 == yKAc)
        #expect(d2 == nil)
    }

    @Test func testSECP521R1() async throws {
        let privateKeyAgreementKey: P521.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: .SECP521R1)
        let privateSigningKey: P521.Signing.PrivateKey = try generateSigningPrivateKey(
            curve: .SECP521R1
        )
        
        let publicKeyAgreementKeyCompact: P521.KeyAgreement.PublicKey = try deriveKeyAgreementPublicKeyCompact(
            from: privateKeyAgreementKey.publicKey.compressedRepresentation,
            curve: .SECP521R1
        )
        let publicSigningKeyCompact: P521.Signing.PublicKey = try deriveSigningPublicKeyCompact(
            from: privateSigningKey.publicKey.compressedRepresentation,
            curve: .SECP521R1
        )
        
        let derivedPrivateKeyAgreementKey: P521.KeyAgreement.PrivateKey = try deriveKeyAgreementPrivateKey(
            from: privateKeyAgreementKey.rawRepresentation,
            curve: .SECP521R1
        )
        let derivedPrivateKeySigningKey: P521.Signing.PrivateKey = try deriveSigningPrivateKey(
            from: privateSigningKey.rawRepresentation,
            curve: .SECP521R1
        )
        
        let (curve1, x1, y1, d1) = try deriveNumbers(from: privateKeyAgreementKey)
        let (curve2, x2, y2, d2) = try deriveNumbers(from: privateKeyAgreementKey.publicKey)
        
        let derivedPublicKeyAgreementKey: P521.KeyAgreement.PublicKey = try derivePublicKeyFromNumbers(
            curve: curve1,
            x: x1,
            y: y1!
        )
        
        let (xKA, yKA) = try deriveKeyAgreementPublicNumbers(
            from: privateKeyAgreementKey.rawRepresentation,
            curve: .SECP521R1
        )
        let (xS, yS) = try deriveSigningPublicNumbers(
            from: privateSigningKey.rawRepresentation,
            curve: .SECP521R1
        )
        
        let (xKAc, yKAc) = try deriveKeyAgreementPublicNumbersCompact(
            from: privateKeyAgreementKey.publicKey.compressedRepresentation,
            curve: .SECP521R1
        )
        let (xSc, ySc) = try deriveSigningPublicNumbersCompact(
            from: privateSigningKey.publicKey.compressedRepresentation,
            curve: .SECP521R1
        )
        
        #expect(privateKeyAgreementKey.rawRepresentation.count == 66)
        #expect(privateSigningKey.rawRepresentation.count == 66)
        
        #expect(publicKeyAgreementKeyCompact.rawRepresentation == derivedPublicKeyAgreementKey.rawRepresentation)
        
        #expect(publicKeyAgreementKeyCompact.rawRepresentation == privateKeyAgreementKey.publicKey.rawRepresentation)
        #expect(publicSigningKeyCompact.rawRepresentation.count == privateSigningKey.publicKey.rawRepresentation.count)
        
        #expect(privateKeyAgreementKey.rawRepresentation == derivedPrivateKeyAgreementKey.rawRepresentation)
        #expect(privateSigningKey.rawRepresentation == derivedPrivateKeySigningKey.rawRepresentation)
        
        #expect(xKA == xKAc)
        #expect(yKA == yKAc)
        #expect(xS == xSc)
        #expect(yS == ySc)
        
        #expect(curve1 == .SECP521R1)
        #expect(curve2 == .SECP521R1)
        #expect(x1 == xKAc)
        #expect(y1 == yKAc)
        #expect(d1 == privateKeyAgreementKey.rawRepresentation)
        #expect(x2 == xKAc)
        #expect(y2 == yKAc)
        #expect(d2 == nil)
    }

    @Test func testED448() async throws {
        let privateSigningKey: Curve448.Signing.PrivateKey = try generateSigningPrivateKey(
            curve: .ED448
        )
        
        let publicSigningKeyCompact: Curve448.Signing.PublicKey = try deriveSigningPublicKeyCompact(
            from: privateSigningKey.publicKey.rawRepresentation,
            curve: .ED448
        )
        let derivedPrivateKeySigningKey: Curve448.Signing.PrivateKey = try deriveSigningPrivateKey(
            from: privateSigningKey.rawRepresentation,
            curve: .ED448
        )
        let (xS, yS) = try deriveSigningPublicNumbers(
            from: privateSigningKey.rawRepresentation,
            curve: .ED448
        )
        let (xSc, ySc) = try deriveSigningPublicNumbersCompact(
            from: privateSigningKey.publicKey.rawRepresentation,
            curve: .ED448
        )
        
        #expect(privateSigningKey.rawRepresentation.count == 57)
        #expect(publicSigningKeyCompact.rawRepresentation.count == 57)
        
        #expect(publicSigningKeyCompact.rawRepresentation.count == privateSigningKey.publicKey.rawRepresentation.count)
        
        #expect(privateSigningKey.rawRepresentation == derivedPrivateKeySigningKey.rawRepresentation)
        
        #expect(xS == xSc)
        #expect(yS == ySc)
    }

    @Test func testED25519() async throws {
        let privateSigningKey: Curve25519.Signing.PrivateKey = try generateSigningPrivateKey(
            curve: .ED25519
        )
        
        let publicSigningKeyCompact: Curve25519.Signing.PublicKey = try deriveSigningPublicKeyCompact(
            from: privateSigningKey.publicKey.rawRepresentation,
            curve: .ED25519
        )
        let derivedPrivateKeySigningKey: Curve25519.Signing.PrivateKey = try deriveSigningPrivateKey(
            from: privateSigningKey.rawRepresentation,
            curve: .ED25519
        )
        let (xS, yS) = try deriveSigningPublicNumbers(
            from: privateSigningKey.rawRepresentation,
            curve: .ED25519
        )
        let (xSc, ySc) = try deriveSigningPublicNumbersCompact(
            from: privateSigningKey.publicKey.rawRepresentation,
            curve: .ED25519
        )
        
        #expect(privateSigningKey.rawRepresentation.count == 32)
        #expect(publicSigningKeyCompact.rawRepresentation.count == 32)
        
        #expect(publicSigningKeyCompact.rawRepresentation.count == privateSigningKey.publicKey.rawRepresentation.count)
        
        #expect(privateSigningKey.rawRepresentation == derivedPrivateKeySigningKey.rawRepresentation)
        
        #expect(xS == xSc)
        #expect(yS == ySc)
    }

    @Test func testX25519() async throws {
        let privateKeyAgreementKey: Curve25519.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: .X25519)
        
        let publicKeyAgreementKeyCompact: Curve25519.KeyAgreement.PublicKey = try deriveKeyAgreementPublicKeyCompact(
            from: privateKeyAgreementKey.publicKey.rawRepresentation,
            curve: .X25519
        )
        
        let derivedPrivateKeyAgreementKey: Curve25519.KeyAgreement.PrivateKey = try deriveKeyAgreementPrivateKey(
            from: privateKeyAgreementKey.rawRepresentation,
            curve: .X25519
        )
        
        let (xKA, yKA) = try deriveKeyAgreementPublicNumbers(
            from: privateKeyAgreementKey.rawRepresentation,
            curve: .X25519
        )
        
        let (xKAc, yKAc) = try deriveKeyAgreementPublicNumbersCompact(
            from: privateKeyAgreementKey.publicKey.rawRepresentation,
            curve: .X25519
        )
        
        #expect(privateKeyAgreementKey.rawRepresentation.count == 32)
        #expect(publicKeyAgreementKeyCompact.rawRepresentation.count == 32)
        
        #expect(publicKeyAgreementKeyCompact.rawRepresentation == privateKeyAgreementKey.publicKey.rawRepresentation)
        
        #expect(privateKeyAgreementKey.rawRepresentation == derivedPrivateKeyAgreementKey.rawRepresentation)
        
        #expect(xKA == xKAc)
        #expect(yKA == yKAc)
    }

    @Test func testX448() async throws {
        let privateKeyAgreementKey: Curve448.KeyAgreement.PrivateKey = try generateKeyAgreementPrivateKey(curve: .X448)
        
        let publicKeyAgreementKeyCompact: Curve448.KeyAgreement.PublicKey = try deriveKeyAgreementPublicKeyCompact(
            from: privateKeyAgreementKey.publicKey.rawRepresentation,
            curve: .X448
        )
        
        let derivedPrivateKeyAgreementKey: Curve448.KeyAgreement.PrivateKey = try deriveKeyAgreementPrivateKey(
            from: privateKeyAgreementKey.rawRepresentation,
            curve: .X448
        )
        
        let (xKA, yKA) = try deriveKeyAgreementPublicNumbers(
            from: privateKeyAgreementKey.rawRepresentation,
            curve: .X448
        )
        
        let (xKAc, yKAc) = try deriveKeyAgreementPublicNumbersCompact(
            from: privateKeyAgreementKey.publicKey.rawRepresentation,
            curve: .X448
        )
        
        #expect(privateKeyAgreementKey.rawRepresentation.count == 56)
        #expect(publicKeyAgreementKeyCompact.rawRepresentation.count == 56)
        
        #expect(publicKeyAgreementKeyCompact.rawRepresentation == privateKeyAgreementKey.publicKey.rawRepresentation)
        
        #expect(privateKeyAgreementKey.rawRepresentation == derivedPrivateKeyAgreementKey.rawRepresentation)
        
        #expect(xKA == xKAc)
        #expect(yKA == yKAc)
    }
}
