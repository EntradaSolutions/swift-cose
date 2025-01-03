import Testing
import Foundation
import PotentCBOR
@testable import SwiftCOSE

struct CoseMessageIdentifierTests {
    
    // MARK: - CoseMessageIdentifier Initialization Tests
    
    @Test func testCoseMessageIdentifierRawValue() async throws {
        #expect(CoseMessageIdentifier(rawValue: 16) == .encrypt0)
        #expect(CoseMessageIdentifier(rawValue: 96) == .encrypt)
        #expect(CoseMessageIdentifier(rawValue: 17) == .mac0)
        #expect(CoseMessageIdentifier(rawValue: 97) == .mac)
        #expect(CoseMessageIdentifier(rawValue: 18) == .sign1)
        #expect(CoseMessageIdentifier(rawValue: 98) == .sign)
        #expect(CoseMessageIdentifier(rawValue: 99) == nil)  // Invalid value
    }
    
    // MARK: - Full Name Conversion Tests
    
    @Test func testCoseMessageIdentifierFromFullName() async throws {
        #expect(CoseMessageIdentifier.fromFullName("COSE_Encrypt0") == .encrypt0)
        #expect(CoseMessageIdentifier.fromFullName("COSE_Encrypt") == .encrypt)
        #expect(CoseMessageIdentifier.fromFullName("COSE_Mac0") == .mac0)
        #expect(CoseMessageIdentifier.fromFullName("COSE_Mac") == .mac)
        #expect(CoseMessageIdentifier.fromFullName("COSE_Sign1") == .sign1)
        #expect(CoseMessageIdentifier.fromFullName("COSE_Sign") == .sign)
        #expect(CoseMessageIdentifier.fromFullName("UNKNOWN") == nil)  // Invalid name
    }
}

struct CoseMessageTests {
    
    // MARK: - Individual CoseMessage Tests
    @Test("Test All Cose Message", arguments: CoseMessageIdentifier.allCases)
    func testCoseMessage(_ msgId: CoseMessageIdentifier) async throws {
        let msg = try CoseMessage.fromId(for: msgId)
        #expect(msg != nil, "\(msgId) should have a message")
    }
    
    // MARK: - Initialization Tests
    
    @Test func testCoseMessageInitialization() async throws {
        let phdr: [CoseHeaderAttribute: Any] = [
            Algorithm(): A128GCM(),
            IV(): Data([0x01, 0x02, 0x03, 0x04])
        ]
        
        let uhdr: [CoseHeaderAttribute: Any] = [
            ContentType(): "application/json"
        ]
        
        let payload = Data("Test Payload".utf8)
        let externalAAD = Data("AAD Data".utf8)
        
        let coseMessage = CoseMessage(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD
        )
        
        #expect(coseMessage.phdr.count == 2, "Protected header should have 2 attributes.")
        #expect(coseMessage.uhdr.count == 1, "Unprotected header should have 1 attribute.")
        #expect(coseMessage.payload == payload, "Payload should match the initialized value.")
        #expect(coseMessage.externalAAD == externalAAD, "External AAD should match the initialized value.")
    }
    
    @Test func testEmptyCoseMessageInitialization() async throws {
        let coseMessage = CoseMessage()
        
        #expect(coseMessage.phdr.isEmpty, "Protected header should be empty.")
        #expect(coseMessage.uhdr.isEmpty, "Unprotected header should be empty.")
        #expect(coseMessage.payload == nil, "Payload should be nil.")
        #expect(coseMessage.externalAAD.isEmpty, "External AAD should be empty.")
    }
    
    // MARK: - Key Tests
    
    @Test func testKeyAssignment() async throws {
        let coseMessage = CoseMessage()
        let symmetricKey = try CoseSymmetricKey(
            k: Data.randomBytes(count: 16)
        )
        
        coseMessage.key = symmetricKey
        
        #expect(coseMessage.key === symmetricKey, "Key should be correctly assigned.")
    }
}
