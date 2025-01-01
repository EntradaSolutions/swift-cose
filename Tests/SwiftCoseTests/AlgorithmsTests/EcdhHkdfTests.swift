import Testing
import Foundation
@testable import SwiftCose

struct EcdhHkdfAlgorithmTests {
    // MARK: - Individual EcdhHkdfAlgorithm Tests
    @Test("Test All EcdhHkdf Algorithms", arguments: [
        CoseAlgorithmIdentifier.ecdhES_A128KW,
        .ecdhES_A192KW,
        .ecdhES_A256KW,
        .ecdhES_HKDF_256,
        .ecdhES_HKDF_512,
        .ecdhSS_A128KW,
        .ecdhSS_A192KW,
        .ecdhSS_A256KW,
        .ecdhSS_HKDF_256,
        .ecdhSS_HKDF_512
    ], [
        CoseCurveIdentifier.p256,
        .p384,
        .p521,
        .secp256k1
    ])
    func testEcdhHkdfAlgorithms(_ algId: CoseAlgorithmIdentifier, _ curveId: CoseCurveIdentifier) async throws {
//        let size: Int
//        if curveId == .p521 {
//            size = 66
//        }  else {
//            size = 32
//        }
        
        let curve = try CoseCurve.fromId(for: curveId)
            
        let privateKey = try EC2Key.generateKey(curve: curve)
        let context = CoseKDFContext(
            algorithm: AESCCM1664128(),
            suppPubInfo: try .init(keyDataLength: 32)
        )
        
        let ecdhHkdf = try EcdhHkdfAlgorithm.fromId(
            for: algId
        ) as! EcdhHkdfAlgorithm
        
        let derivedKey = try ecdhHkdf.deriveKEK(
            curve: curve,
            privateKey: privateKey,
            publicKey: privateKey,
            context: context
        )
        
        #expect(
            derivedKey.count == 32,
            "Derived key length should be \(32) bytes."
        )
    }
}
