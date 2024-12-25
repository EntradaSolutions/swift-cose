import Testing
import Foundation
@testable import SwiftCose

struct AesKwAlgorithmTests {
    
    @Test func testA128KW() async throws {
        let aesKw = A128KW()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesKw.keyLength!
        )
        let data = "SensitiveData128".data(using: .utf8)!
        
        let wrappedKey = try aesKw.keyWrap(kek: key, data: data)
        let unwrappedKey = try aesKw.keyUnwrap(kek: key, data: wrappedKey)
        
        #expect(data == unwrappedKey, "Unwrapped data does not match the original data.")
    }
    
    @Test func testA192KW() async throws {
        let aesKw = A192KW()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesKw.keyLength!
        )
        let data = "SensitiveData192".data(using: .utf8)!
        
        let wrappedKey = try aesKw.keyWrap(kek: key, data: data)
        let unwrappedKey = try aesKw.keyUnwrap(kek: key, data: wrappedKey)
        
        #expect(data == unwrappedKey, "Unwrapped data does not match the original data.")
    }
    
    @Test func testA256KW() async throws {
        let aesKw = A256KW()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesKw.keyLength!
        )
        let data = "SensitiveData256".data(using: .utf8)!
        
        let wrappedKey = try aesKw.keyWrap(kek: key, data: data)
        let unwrappedKey = try aesKw.keyUnwrap(kek: key, data: wrappedKey)
        
        #expect(data == unwrappedKey, "Unwrapped data does not match the original data.")
    }
    
    @Test func testKeyLengthFail() async throws {
        let aesKw = A128KW()
        let invalidKey = try CoseSymmetricKey.generateKey(
            keyLength: 24 // Wrong key length to induce failure
        )
        let data = "FailureCase".data(using: .utf8)!
        
        #expect(throws: CoseError.self) {
            try aesKw.keyWrap(kek: invalidKey, data: data)
        }
        
        #expect(throws: CoseError.self) {
            try aesKw.keyUnwrap(kek: invalidKey, data: data)
        }
    }
    
    @Test func testDataLengthFail() async throws {
        let aesKw = A128KW()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesKw.keyLength!
        )
        let data = "".data(using: .utf8)!
        
        #expect(throws: CoseError.self) {
            try aesKw.keyWrap(kek: key, data: data)
        }
        
        #expect(throws: CoseError.self) {
            try aesKw.keyUnwrap(kek: key, data: data)
        }
    }
    
    @Test func testData8MultipleFail() async throws {
        let aesKw = A128KW()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesKw.keyLength!
        )
        let data = "SensitiveData128 is the content".data(using: .utf8)!
        
        #expect(throws: CoseError.self) {
            try aesKw.keyWrap(kek: key, data: data)
        }
        
        #expect(throws: CoseError.self) {
            try aesKw.keyUnwrap(kek: key, data: data)
        }
    }
}
