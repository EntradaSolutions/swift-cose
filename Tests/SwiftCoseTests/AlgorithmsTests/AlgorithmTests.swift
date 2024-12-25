import Testing
import Foundation
@testable import SwiftCose

struct AlgorithmsTests {
    
    // MARK: - CoseAlgorithmIdentifier Tests
    
    @Test func testCoseAlgorithmIdentifierFromFullName() async throws {
        #expect(CoseAlgorithmIdentifier.fromFullName("AES_CCM_16_64_128") == .aesCCM_16_64_128)
        #expect(CoseAlgorithmIdentifier.fromFullName("AES_CCM_16_64_256") == .aesCCM_16_64_256)
        #expect(CoseAlgorithmIdentifier.fromFullName("AES_CCM_64_64_128") == .aesCCM_64_64_128)
        #expect(CoseAlgorithmIdentifier.fromFullName("AES_CCM_64_64_256") == .aesCCM_64_64_256)
        #expect(CoseAlgorithmIdentifier.fromFullName("AES_CCM_16_128_128") == .aesCCM_16_128_128)
        #expect(CoseAlgorithmIdentifier.fromFullName("AES_CCM_16_128_256") == .aesCCM_16_128_256)
        #expect(CoseAlgorithmIdentifier.fromFullName("AES_CCM_64_128_128") == .aesCCM_64_128_128)
        #expect(CoseAlgorithmIdentifier.fromFullName("AES_CCM_64_128_256") == .aesCCM_64_128_256)
        #expect(CoseAlgorithmIdentifier.fromFullName("AES_MAC_128_64") == .aesMAC_128_64)
        #expect(CoseAlgorithmIdentifier.fromFullName("AES_MAC_128_128") == .aesMAC_128_128)
        #expect(CoseAlgorithmIdentifier.fromFullName("A128GCM") == .aesGCM_128)
        #expect(CoseAlgorithmIdentifier.fromFullName("AES_MAC_256_128") == .aesMAC_256_128)
        #expect(CoseAlgorithmIdentifier.fromFullName("A192GCM") == .aesGCM_192)
        #expect(CoseAlgorithmIdentifier.fromFullName("A256GCM") == .aesGCM_256)
        #expect(CoseAlgorithmIdentifier.fromFullName("A128KW") == .aesKW_128)
        #expect(CoseAlgorithmIdentifier.fromFullName("A192KW") == .aesKW_192)
        #expect(CoseAlgorithmIdentifier.fromFullName("A256KW") == .aesKW_256)
        #expect(CoseAlgorithmIdentifier.fromFullName("DIRECT_HKDF_AES_128") == .directHKDFAES128)
        #expect(CoseAlgorithmIdentifier.fromFullName("DIRECT_HKDF_AES_256") == .directHKDFAES256)
        #expect(CoseAlgorithmIdentifier.fromFullName("DIRECT_HKDF_SHA_256") == .directHKDFSHA256)
        #expect(CoseAlgorithmIdentifier.fromFullName("DIRECT_HKDF_SHA_512") == .direcHKDFSHA512)
        #expect(CoseAlgorithmIdentifier.fromFullName("AES_MAC_256_64") == .aesMAC_256_64)
        #expect(CoseAlgorithmIdentifier.fromFullName("DIRECT") == .direct)
        #expect(CoseAlgorithmIdentifier.fromFullName("EDDSA") == .edDSA)
        #expect(CoseAlgorithmIdentifier.fromFullName("ECDH_ES_A128KW") == .ecdhES_A128KW)
        #expect(CoseAlgorithmIdentifier.fromFullName("ECDH_ES_A192KW") == .ecdhES_A192KW)
        #expect(CoseAlgorithmIdentifier.fromFullName("ECDH_ES_A256KW") == .ecdhES_A256KW)
        #expect(CoseAlgorithmIdentifier.fromFullName("ECDH_ES_HKDF_256") == .ecdhES_HKDF_256)
        #expect(CoseAlgorithmIdentifier.fromFullName("ECDH_ES_HKDF_512") == .ecdhES_HKDF_512)
        #expect(CoseAlgorithmIdentifier.fromFullName("ECDH_SS_A128KW") == .ecdhSS_A128KW)
        #expect(CoseAlgorithmIdentifier.fromFullName("ECDH_SS_A192KW") == .ecdhSS_A192KW)
        #expect(CoseAlgorithmIdentifier.fromFullName("ECDH_SS_A256KW") == .ecdhSS_A256KW)
        #expect(CoseAlgorithmIdentifier.fromFullName("ECDH_SS_HKDF_256") == .ecdhSS_HKDF_256)
        #expect(CoseAlgorithmIdentifier.fromFullName("ECDH_SS_HKDF_512") == .ecdhSS_HKDF_512)
        #expect(CoseAlgorithmIdentifier.fromFullName("ES256") == .es256)
        #expect(CoseAlgorithmIdentifier.fromFullName("ES384") == .es384)
        #expect(CoseAlgorithmIdentifier.fromFullName("ES512") == .es512)
        #expect(CoseAlgorithmIdentifier.fromFullName("HMAC_256") == .hmacSHA256)
        #expect(CoseAlgorithmIdentifier.fromFullName("HMAC_256_64") == .hmacSHA256_64)
        #expect(CoseAlgorithmIdentifier.fromFullName("HMAC_384") == .hmacSHA384)
        #expect(CoseAlgorithmIdentifier.fromFullName("HMAC_512") == .hmacSHA512)
        #expect(CoseAlgorithmIdentifier.fromFullName("PS256") == .ps256)
        #expect(CoseAlgorithmIdentifier.fromFullName("PS384") == .ps384)
        #expect(CoseAlgorithmIdentifier.fromFullName("PS512") == .ps512)
        #expect(CoseAlgorithmIdentifier.fromFullName("RSAES_OAEP_SHA_1") == .rsa_ES_OAEP_SHA1)
        #expect(CoseAlgorithmIdentifier.fromFullName("RSAES_OAEP_SHA_256") == .rsa_ES_OAEP_SHA256)
        #expect(CoseAlgorithmIdentifier.fromFullName("RSAES_OAEP_SHA_512") == .rsa_ES_OAEP_SHA512)
        #expect(CoseAlgorithmIdentifier.fromFullName("RS1") == .rsa_PKCS1_SHA1)
        #expect(CoseAlgorithmIdentifier.fromFullName("RS256") == .rsa_PKCS1_SHA256)
        #expect(CoseAlgorithmIdentifier.fromFullName("RS384") == .rsa_PKCS1_SHA384)
        #expect(CoseAlgorithmIdentifier.fromFullName("RS512") == .rsa_PKCS1_SHA512)
        #expect(CoseAlgorithmIdentifier.fromFullName("SHA-1") == .sha1)
        #expect(CoseAlgorithmIdentifier.fromFullName("SHA-256") == .sha256)
        #expect(CoseAlgorithmIdentifier.fromFullName("SHA-256/64") == .sha256_64)
        #expect(CoseAlgorithmIdentifier.fromFullName("SHA-384") == .sha384)
        #expect(CoseAlgorithmIdentifier.fromFullName("SHA-512") == .sha512)
        #expect(CoseAlgorithmIdentifier.fromFullName("SHA-512/256") == .sha512_256)
        #expect(CoseAlgorithmIdentifier.fromFullName("SHAKE-128") == .shake128)
        #expect(CoseAlgorithmIdentifier.fromFullName("SHAKE-256") == .shake256)
        #expect(CoseAlgorithmIdentifier.fromFullName("UNKNOWN") == nil)
    }
    
    @Test func testCoseAlgorithmIdentifierRawValue() async throws {
        #expect(CoseAlgorithmIdentifier(rawValue: 10) == .aesCCM_16_64_128)
        #expect(CoseAlgorithmIdentifier(rawValue: 11) == .aesCCM_16_64_256)
        #expect(CoseAlgorithmIdentifier(rawValue: 12) == .aesCCM_64_64_128)
        #expect(CoseAlgorithmIdentifier(rawValue: 13) == .aesCCM_64_64_256)
        #expect(CoseAlgorithmIdentifier(rawValue: 30) == .aesCCM_16_128_128)
        #expect(CoseAlgorithmIdentifier(rawValue: 31) == .aesCCM_16_128_256)
        #expect(CoseAlgorithmIdentifier(rawValue: 32) == .aesCCM_64_128_128)
        #expect(CoseAlgorithmIdentifier(rawValue: 33) == .aesCCM_64_128_256)
        #expect(CoseAlgorithmIdentifier(rawValue: 1) == .aesGCM_128)
        #expect(CoseAlgorithmIdentifier(rawValue: 2) == .aesGCM_192)
        #expect(CoseAlgorithmIdentifier(rawValue: 3) == .aesGCM_256)
        #expect(CoseAlgorithmIdentifier(rawValue: -3) == .aesKW_128)
        #expect(CoseAlgorithmIdentifier(rawValue: -4) == .aesKW_192)
        #expect(CoseAlgorithmIdentifier(rawValue: -5) == .aesKW_256)
        #expect(CoseAlgorithmIdentifier(rawValue: 14) == .aesMAC_128_64)
        #expect(CoseAlgorithmIdentifier(rawValue: 15) == .aesMAC_256_64)
        #expect(CoseAlgorithmIdentifier(rawValue: 25) == .aesMAC_128_128)
        #expect(CoseAlgorithmIdentifier(rawValue: 26) == .aesMAC_256_128)
        #expect(CoseAlgorithmIdentifier(rawValue: -6) == .direct)
        #expect(CoseAlgorithmIdentifier(rawValue: -12) == .directHKDFAES128)
        #expect(CoseAlgorithmIdentifier(rawValue: -13) == .directHKDFAES256)
        #expect(CoseAlgorithmIdentifier(rawValue: -10) == .directHKDFSHA256)
        #expect(CoseAlgorithmIdentifier(rawValue: -11) == .direcHKDFSHA512)
        #expect(CoseAlgorithmIdentifier(rawValue: -8) == .edDSA)
        #expect(CoseAlgorithmIdentifier(rawValue: -7) == .es256)
        #expect(CoseAlgorithmIdentifier(rawValue: -35) == .es384)
        #expect(CoseAlgorithmIdentifier(rawValue: -36) == .es512)
        #expect(CoseAlgorithmIdentifier(rawValue: -29) == .ecdhES_A128KW)
        #expect(CoseAlgorithmIdentifier(rawValue: -30) == .ecdhES_A192KW)
        #expect(CoseAlgorithmIdentifier(rawValue: -31) == .ecdhES_A256KW)
        #expect(CoseAlgorithmIdentifier(rawValue: -25) == .ecdhES_HKDF_256)
        #expect(CoseAlgorithmIdentifier(rawValue: -26) == .ecdhES_HKDF_512)
        #expect(CoseAlgorithmIdentifier(rawValue: -32) == .ecdhSS_A128KW)
        #expect(CoseAlgorithmIdentifier(rawValue: -33) == .ecdhSS_A192KW)
        #expect(CoseAlgorithmIdentifier(rawValue: -34) == .ecdhSS_A256KW)
        #expect(CoseAlgorithmIdentifier(rawValue: -27) == .ecdhSS_HKDF_256)
        #expect(CoseAlgorithmIdentifier(rawValue: -28) == .ecdhSS_HKDF_512)
        #expect(CoseAlgorithmIdentifier(rawValue: 5) == .hmacSHA256)
        #expect(CoseAlgorithmIdentifier(rawValue: 4) == .hmacSHA256_64)
        #expect(CoseAlgorithmIdentifier(rawValue: 6) == .hmacSHA384)
        #expect(CoseAlgorithmIdentifier(rawValue: 7) == .hmacSHA512)
        #expect(CoseAlgorithmIdentifier(rawValue: -37) == .ps256)
        #expect(CoseAlgorithmIdentifier(rawValue: -38) == .ps384)
        #expect(CoseAlgorithmIdentifier(rawValue: -39) == .ps512)
        #expect(CoseAlgorithmIdentifier(rawValue: -41) == .rsa_ES_OAEP_SHA256)
        #expect(CoseAlgorithmIdentifier(rawValue: -42) == .rsa_ES_OAEP_SHA512)
        #expect(CoseAlgorithmIdentifier(rawValue: -65535) == .rsa_PKCS1_SHA1)
        #expect(CoseAlgorithmIdentifier(rawValue: -257) == .rsa_PKCS1_SHA256)
        #expect(CoseAlgorithmIdentifier(rawValue: -258) == .rsa_PKCS1_SHA384)
        #expect(CoseAlgorithmIdentifier(rawValue: -259) == .rsa_PKCS1_SHA512)
        #expect(CoseAlgorithmIdentifier(rawValue: -40) == .rsa_ES_OAEP_SHA1)
        #expect(CoseAlgorithmIdentifier(rawValue: -14) == .sha1)
        #expect(CoseAlgorithmIdentifier(rawValue: -16) == .sha256)
        #expect(CoseAlgorithmIdentifier(rawValue: -15) == .sha256_64)
        #expect(CoseAlgorithmIdentifier(rawValue: -43) == .sha384)
        #expect(CoseAlgorithmIdentifier(rawValue: -44) == .sha512)
        #expect(CoseAlgorithmIdentifier(rawValue: -17) == .sha512_256)
        #expect(CoseAlgorithmIdentifier(rawValue: -18) == .shake128)
        #expect(CoseAlgorithmIdentifier(rawValue: -45) == .shake256)
        #expect(CoseAlgorithmIdentifier(rawValue: 99) == nil)  // Invalid value
    }
    
    // MARK: - CoseAlgorithm Instance Tests
    
    @Test func testCoseAlgorithmFromIdFail() async throws {
        #expect(throws: CoseError.self) {
            let _ = try CoseAlgorithm.fromId(for: [])
        }
        
        #expect(throws: CoseError.self) {
            let _ = try CoseAlgorithm.fromId(for: Data())
        }
        
        #expect(throws: CoseError.self) {
            let _ = try CoseAlgorithm.fromId(for: 500)
        }
        
        #expect(throws: CoseError.self) {
            let _ = try CoseAlgorithm.fromId(for: "INVALID_ALG")
        }
    }
    
    // MARK: - Individual CoseAlgorithm Tests
    @Test("Test All Cose Algorithms", arguments: CoseAlgorithmIdentifier.allCases)
    func testCoseAlgorithm(_ algId: CoseAlgorithmIdentifier) async throws {
        let alg1 = try CoseAlgorithm.fromId(for: algId)
        let alg2 = try CoseAlgorithm.fromId(for: alg1.fullname)
        let alg3 = try CoseAlgorithm.fromId(for: algId.rawValue)
        
        #expect(alg1 == alg2)
        #expect(alg2 == alg3)
        #expect(alg1.identifier == algId.rawValue)
        #expect(alg1.identifier == CoseAlgorithmIdentifier.fromFullName(alg1.fullname)?.rawValue)
    }
}
