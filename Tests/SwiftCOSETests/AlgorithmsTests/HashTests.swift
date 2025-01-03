import Testing
import Foundation
@testable import SwiftCOSE

struct HashAlgorithmsTests {
    
    @Test func testComputeHashFail() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = HashAlgorithm(
            identifier: .aesCCM_16_64_128,
            fullname: "SHA-1",
            truncSize: 0
        )
        
        #expect(throws: CoseError.self) {
            _ = try hashAlgorithm.computeHash(data: data)
        }
    }
    
    @Test func testSha1() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Sha1()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3".hexStringToData
        
        #expect(hash == expectedHash, "SHA-1 hash does not match expected value.")
    }
    
    @Test func testSha256() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Sha256()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = Data([0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08])
        
        #expect(hash == expectedHash, "SHA-256 hash does not match expected value.")
    }
    
    @Test func testSha256Trunc64() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Sha256Trunc64()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = Data([0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65])
        
        #expect(hash == expectedHash, "SHA-256/64 truncated hash does not match expected value.")
    }
    
    @Test func testSha384() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Sha384()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = "e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd".hexStringToData
        
        #expect(hash == expectedHash, "SHA-384 hash does not match expected value.")
    }
    
    @Test func testSha512() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Sha512()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14".hexStringToData
        
        #expect(hash == expectedHash, "SHA-512 hash does not match expected value.")
    }
    
    @Test func testSha512Trunc64() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Sha512Trunc64()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = Data([
            0x9e, 0xce, 0x08, 0x6e, 0x9b, 0xac, 0x49, 0x1f,
            0xac, 0x5c, 0x1d, 0x10, 0x46, 0xca, 0x11, 0xd7,
            0x37, 0xb9, 0x2a, 0x2b, 0x2e, 0xbd, 0x93, 0xf0,
            0x05, 0xd7, 0xb7, 0x10, 0x11, 0x0c, 0x0a, 0x67
        ])
        
        #expect(hash == expectedHash, "SHA-512/256 hash does not match expected value.")
        #expect(hash.count == 32, "SHA-512/256 truncated hash length does not match expected value.")
    }
    
    @Test func testShake128() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Shake128()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = "d3b0aa9cd8b7255622cebc631e867d4093d6f6010191a53973c45fec9b07c774".hexStringToData
        
        #expect(hash.count == 256 / 8, "SHAKE-128 hash length does not match expected value.")
        #expect(hash == expectedHash, "SHAKE-128 hash does not match expected value.")
    }
    
    @Test func testShake256() async throws {
        let data = "test".data(using: .utf8)!
        let hashAlgorithm = Shake256()
        
        let hash = try hashAlgorithm.computeHash(data: data)
        let expectedHash = "b54ff7255705a71ee2925e4a3e30e41aed489a579d5595e0df13e32e1e4dd202a7c7f68b31d6418d9845eb4d757adda6ab189e1bb340db818e5b3bc725d992fa".hexStringToData
        
        #expect(hash.count == 512 / 8, "SHAKE-256 hash length does not match expected value.")
        #expect(hash == expectedHash, "SHAKE-256 hash does not match expected value.")
    }
}
