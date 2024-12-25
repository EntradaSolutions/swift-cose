import Testing
import Foundation
@testable import SwiftCose

struct RsaAlgorithmTests {
    
    @Test("Test RSA signing and verification", arguments: zip([
        CoseAlgorithmIdentifier.ps256,
        .ps384,
        .ps512,
        .rsa_PKCS1_SHA1,
        .rsa_PKCS1_SHA256,
        .rsa_PKCS1_SHA384,
        .rsa_PKCS1_SHA512
    ], [1024,1024,2048,1024,1024,1024, 1024]))
    func testRsaSignVerify(_ algId: CoseAlgorithmIdentifier, _ keyBits: Int) async throws {
        let message = "Test RSA Sign and Verify".data(using: .utf8)!
        
        // Generate RSA Key - use 1024/2048 bits for testing
        let rsaKey = try RSAKey.generateKey(keyBits: keyBits)
        
        let rsaAlg = try RsaAlgorithm.fromId(
            for: algId
        ) as! RsaAlgorithm
        
        // Sign message
        let signature = try rsaAlg.sign(key: rsaKey, data: message)
        
        // Verify signature
        let isValid = try rsaAlg.verify(key: rsaKey, data: message, signature: signature)
        
        #expect(
            isValid,
            "RSA signature verification failed"
        )
    }
    
    @Test("Test RSA encryption and decryption with OAEP", arguments: zip([
        CoseAlgorithmIdentifier.rsa_ES_OAEP_SHA1,
        .rsa_ES_OAEP_SHA256,
        .rsa_ES_OAEP_SHA512
    ], [1024,1024,2048]))
    func testRsaEncryptDecrypt(_ algId: CoseAlgorithmIdentifier, _ keyBits: Int) async throws {
        let plaintext = "Test RSA Encryption and Decryption".data(using: .utf8)!
        
        // Generate RSA Key - 1024/2048 bits for encryption tests
        let rsaKey = try RSAKey.generateKey(keyBits: keyBits)
        
        let rsaAlg = try RsaOaep.fromId(
            for: algId
        ) as! RsaOaep
        
        // Encrypt the data
        let ciphertext = try rsaAlg.keyWrap(key: rsaKey, data: plaintext)
        
        // Decrypt the data
        let decrypted = try rsaAlg.keyUnwrap(key: rsaKey, data: ciphertext)
        
        #expect(
            decrypted == plaintext,
            "RSA decryption failed. Expected \(plaintext), got \(decrypted)"
        )
    }
    
//    @Test("Test RSA encryption and decryption", arguments: [
//        RsaOaep()
//    ])
//    func testRsaEncryptDecrypt(_ rsaAlg: RsaAlgorithm) async throws {
//        let plaintext = "Test RSA Encryption and Decryption".data(using: .utf8)!
//        
//        // Generate RSA Key
//        let rsaKey = try RSAKey.generateKey(keySize: 2048)
//        
//        // Encrypt
//        guard let rsaOaep = rsaAlg as? RsaOaep else {
//            throw CoseError.valueError("Algorithm must support OAEP")
//        }
//        
//        let ciphertext = try rsaOaep.keyWrap(key: rsaKey, data: plaintext)
//        
//        // Decrypt
//        let decrypted = try rsaOaep.keyUnwrap(key: rsaKey, data: ciphertext)
//        
//        #expect(
//            decrypted == plaintext,
//            "RSA decryption failed. Expected \(plaintext), got \(decrypted)"
//        )
//    }
//    
//    @Test("Test RSA sign with unsupported padding")
//    func testRsaUnsupportedPadding() async throws {
//        let rsaPkcs1 = RsaPkcs1Sha256()
//        let message = "Unsupported Padding Test".data(using: .utf8)!
//        let rsaKey = try RSAKey.generateKey(keySize: 2048)
//        
//        do {
//            _ = try rsaPkcs1.sign(key: rsaKey, data: message)
//        } catch let error as CoseError {
//            #expect(
//                error.localizedDescription.contains("Unsupported padding"),
//                "Expected unsupported padding error"
//            )
//        }
//    }
//    
//    @Test("Test RSA verification failure")
//    func testRsaVerificationFail() async throws {
//        let rsaAlg = Ps256()
//        let message = "Test Verification Fail".data(using: .utf8)!
//        let rsaKey = try RSAKey.generateKey(keySize: 2048)
//        
//        let tamperedMessage = "Tampered Message".data(using: .utf8)!
//        let signature = try rsaAlg.sign(key: rsaKey, data: message)
//        
//        let isValid = try rsaAlg.verify(key: rsaKey, data: tamperedMessage, signature: signature)
//        
//        #expect(
//            !isValid,
//            "Expected verification to fail for tampered message"
//        )
//    }
}
