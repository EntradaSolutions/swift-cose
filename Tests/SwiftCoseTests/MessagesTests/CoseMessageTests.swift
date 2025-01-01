import Testing
import Foundation
import PotentCBOR
@testable import SwiftCose

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
    
    // MARK: - Encoding Tests
    
//    @Test func testCoseMessageEncoding() async throws {
//        let phdr: [CoseHeaderAttribute: Any] = [
//            Algorithm(): A128GCM(),
//            IV(): Data([0x01, 0x02, 0x03, 0x04])
//        ]
//        
//        let uhdr: [CoseHeaderAttribute: Any] = [
//            ContentType(): "application/json"
//        ]
//        let payload = Data("Encode Test".utf8)
//        let coseMessage = CoseMessage(
//            phdr: phdr,
//            uhdr: uhdr,
//            payload: payload
//        )
//        
//        let message = [
//            coseMessage.phdrEncoded.toCBOR,
//            CBOR.fromAny(coseMessage.uhdrEncoded),
//            payload.toCBOR
//        ]
//        let encoded = try coseMessage.encode(message: message)
//        
//        let decoded = try CBORSerialization.cbor(from: encoded)
//        
//        #expect(
//            decoded.tag?.integerValue() == coseMessage.cborTag,
//            "CBOR tag should match the cborTag of the message."
//        )
////        #expect(decoded.value.arrayValue?.count == 1, "Encoded CBOR should contain one array item.")
//    }
    
//    @Test func testEncodingWithoutTag() async throws {
//        let coseMessage = CoseMessage()
//        let message = [CBOR.byteString(Data("No Tag".utf8))]
//        
//        let encoded = try coseMessage.encode(message: message, tag: false)
//        let decoded = try CBORSerialization.cbor(from: encoded)
//        
//        #expect(decoded.arrayValue?.count == 1, "Encoded CBOR without tag should contain one item.")
//    }
//    
//    // MARK: - Decoding Tests
//    
//    @Test func testCoseMessageDecoding() async throws {
//        let payload = Data("Decode Test".utf8)
//        let coseMessage = CoseMessage(payload: payload)
//        
//        let encoded = try coseMessage.encode(message: [CBOR.byteString(payload)])
//        let decoded = try CoseMessage.decode(CoseMessage.self, from: encoded)
//        
//        #expect(decoded.payload == payload, "Decoded message payload should match the original.")
//    }
//    
//    @Test func testDecodingFailure() async throws {
//        let invalidData = Data([0x01, 0x02, 0x03])  // Not valid CBOR
//        
//        #expect(throws: CoseError.self) {
//            let _ = try CoseMessage.decode(CoseMessage.self, from: invalidData)
//        }
//    }
//    
//    // MARK: - AAD Tests
//    
//    @Test func testExternalAADAssignment() async throws {
//        let coseMessage = CoseMessage()
//        let aadData = Data("External AAD".utf8)
//        
//        coseMessage.externalAAD = aadData
//        
//        #expect(coseMessage.externalAAD == aadData, "External AAD should match the assigned value.")
//        
//        #expect(throws: CoseError.self) {
//            coseMessage.externalAAD = "Invalid AAD" as? Data
//        }
//    }
//    
//    // MARK: - Header Encoding
//    
//    @Test func testBaseStructureEncoding() async throws {
//        let coseMessage = CoseMessage()
//        var structure: [CBOR] = []
//        
//        coseMessage.baseStructure(&structure)
//        
//        #expect(structure.count == 2, "Base structure should have 2 items.")
//        #expect(structure[1] == coseMessage.externalAAD.toCBOR, "Second element should be external AAD.")
//    }
}
