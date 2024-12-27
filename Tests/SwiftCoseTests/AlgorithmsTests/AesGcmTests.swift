import Testing
import Foundation
@testable import SwiftCose

struct AesGcmAlgorithmTests {
    
    @Test func testA128GCM() async throws {
        let aesGcm = A128GCM()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesGcm.keyLength!
        )
        let iv = "DDDC08972DF9BE62855291A1".hexStringToData
        let plaintext = "This is the content.".data(using: .utf8)!
        let aad = "".data(using: .utf8)!
        
        let encryptedData = try aesGcm.encrypt(
            key: key,
            nonce: iv,
            data: plaintext,
            aad: aad
        )
        let decryptedData = try aesGcm.decrypt(
            key: key,
            nonce: iv,
            ciphertext: encryptedData,
            aad: aad
        )
        
        #expect(plaintext == decryptedData, "Decrypted data does not match the original plaintext.")
    }
    
    @Test func testA192GCM() async throws {
        let aesGcm = A192GCM()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesGcm.keyLength!
        )
        let iv = "DDDC08972DF9BE62855291A1".hexStringToData
        let plaintext = "This is the content.".data(using: .utf8)!
        let aad = "".data(using: .utf8)!
        
        let encryptedData = try aesGcm.encrypt(
            key: key,
            nonce: iv,
            data: plaintext,
            aad: aad
        )
        let decryptedData = try aesGcm.decrypt(
            key: key,
            nonce: iv,
            ciphertext: encryptedData,
            aad: aad
        )
        
        #expect(plaintext == decryptedData, "Decrypted data does not match the original plaintext.")
    }
    
    @Test func testA256GCM() async throws {
        let aesGcm = A256GCM()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesGcm.keyLength!
        )
        let iv = "DDDC08972DF9BE62855291A1".hexStringToData
        let plaintext = "This is the content.".data(using: .utf8)!
        let aad = "".data(using: .utf8)!
        
        let encryptedData = try aesGcm.encrypt(
            key: key,
            nonce: iv,
            data: plaintext,
            aad: aad
        )
        let decryptedData = try aesGcm.decrypt(
            key: key,
            nonce: iv,
            ciphertext: encryptedData,
            aad: aad
        )
        
        #expect(plaintext == decryptedData, "Decrypted data does not match the original plaintext.")
    }
    
    @Test func testEncryptFail() async throws {
        let aesGcm = A128GCM()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesGcm.keyLength!
        )
        let iv = "".hexStringToData
        let plaintext = "This is the content.".data(using: .utf8)
        let aad = "".data(using: .utf8)!
        
        #expect(throws: CoseError.self) {
            try aesGcm.encrypt(
                key: key,
                nonce: iv,
                data: plaintext!,
                aad: aad
            )
        }
        
        #expect(throws: CoseError.self) {
            try aesGcm.decrypt(
                key: key,
                nonce: iv,
                ciphertext: plaintext!,
                aad: aad
            )
        }
    }
}
