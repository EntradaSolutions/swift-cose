import Testing
import Foundation
@testable import SwiftCose

struct CoseSymmetricKeyTests {
    
    // MARK: - Test Initialization
    
    @Test func testSymmetricKeyInitialization() async throws {
        let keyData = Data.randomBytes(count: 32)
        
        let key = try CoseSymmetricKey(k: keyData)
        
        #expect(key.k == keyData)
    }
    
    // MARK: - Test Key Generation
    
    @Test func testKeyGeneration() async throws {
        let keyLengths = [16, 24, 32]
        
        for length in keyLengths {
            let key = try CoseSymmetricKey.generateKey(keyLength: length)
            #expect(key.k.count == length)
        }
    }
    
    // MARK: - Test Invalid Key Length
    
    @Test func testInvalidKeyLength() async throws {
        let invalidLength = 20  // Not 16, 24, or 32
        
        #expect(throws: CoseError.self) {
            _ = try CoseSymmetricKey.generateKey(keyLength: invalidLength)
        }
    }
    
    // MARK: - Test From Dictionary
    
    @Test func testFromDictionary() async throws {
        let keyData = Data.randomBytes(count: 32)
        let keyDict: [AnyHashable: Any] = [
            SymKpK(): keyData
        ]
        
        let key = try CoseSymmetricKey.fromDictionary(keyDict)
        
        #expect(key.k == keyData)
    }
    
    // MARK: - Test Key Deletion
    
    @Test func testKeyDeletion() async throws {
        let keyData = Data.randomBytes(count: 32)
        let key = try CoseSymmetricKey(k: keyData)

        #expect(throws: CoseError.self) {
            try key.delete(key: SymKpK())  // Deleting key should fail
        }
    }
    
    // MARK: - Test Description
    
    @Test func testDescription() async throws {
        let keyData = Data.randomBytes(count: 32)
        let key = try CoseSymmetricKey(k: keyData)
        
        let description = key.description
        
        #expect(description.contains("COSE_Key"))
        #expect(description.contains("Symmetric"))
    }
}
