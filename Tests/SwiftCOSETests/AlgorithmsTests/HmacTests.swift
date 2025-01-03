import Testing
import Foundation
@testable import SwiftCOSE


struct HmacAlgorithmTests {
    @Test("Test HMAC Algorithm compute hash", arguments: [
        CoseAlgorithmIdentifier.hmacSHA256,
        .hmacSHA256_64,
        .hmacSHA384,
        .hmacSHA512
    ])
    func testHmacAlgorithmComputeTag(_ algId: CoseAlgorithmIdentifier) async throws {
        let hmacAlg = try HmacAlgorithm.fromId(
            for: algId
        ) as! HmacAlgorithm
        
        let message = "Hello, HMAC!".data(using: .utf8)!
        
        let key = try CoseSymmetricKey.generateKey(keyLength: 16)
        
        let hmac = try hmacAlg.computeTag(key: key, data: message)
        
        let verified = try hmacAlg.verifyTag(key: key, tag: hmac, data: message)

        #expect(
            verified,
            "HMAC verification failed"
        )
        
    }
}

