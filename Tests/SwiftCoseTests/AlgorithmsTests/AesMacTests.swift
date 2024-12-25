import Testing
import Foundation
@testable import SwiftCose

struct AesMacAlgorithmTests {
    
    @Test func testAESMAC12864() async throws {
        let aesMac = AESMAC12864()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesMac.keyLength
        )
        let data = "Test Data for MAC".data(using: .utf8)!
        
        let tag = try aesMac.computeTag(key: key, data: data)
        let isValid = try aesMac.verifyTag(key: key, tag: tag, data: data)
        
        #expect(isValid, "Tag verification failed for AESMAC12864.")
    }
    
    @Test func testAESMAC25664() async throws {
        let aesMac = AESMAC25664()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesMac.keyLength
        )
        let data = "Test Data 256-bit".data(using: .utf8)!
        
        let tag = try aesMac.computeTag(key: key, data: data)
        let isValid = try aesMac.verifyTag(key: key, tag: tag, data: data)
        
        #expect(isValid, "Tag verification failed for AESMAC25664.")
    }
    
    @Test func testAESMAC128128() async throws {
        let aesMac = AESMAC128128()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesMac.keyLength
        )
        let data = "Longer test data for MAC 128-bit".data(using: .utf8)!
        
        let tag = try aesMac.computeTag(key: key, data: data)
        let isValid = try aesMac.verifyTag(key: key, tag: tag, data: data)
        
        #expect(isValid, "Tag verification failed for AESMAC128128.")
    }
    
    @Test func testAESMAC256128() async throws {
        let aesMac = AESMAC256128()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesMac.keyLength
        )
        let data = "Another test for 256-bit MAC".data(using: .utf8)!
        
        let tag = try aesMac.computeTag(key: key, data: data)
        let isValid = try aesMac.verifyTag(key: key, tag: tag, data: data)
        
        #expect(isValid, "Tag verification failed for AESMAC256128.")
    }
    
    @Test func testAESMACVerifyTagFailure() async throws {
        let aesMac = AESMAC128128()
        let key = try CoseSymmetricKey.generateKey(
            keyLength: aesMac.keyLength
        )
        let data = "Test data".data(using: .utf8)!
        let tamperedData = "Tampered data".data(using: .utf8)!
        
        let tag = try aesMac.computeTag(key: key, data: data)
        let isValid = try aesMac.verifyTag(
            key: key,
            tag: tag,
            data: tamperedData
        )
        
        #expect(!isValid, "Verification should fail for tampered data.")
    }
}
