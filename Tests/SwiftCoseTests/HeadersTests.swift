import Testing
import Foundation
@testable import SwiftCose

struct HeadersTests {
    
    // MARK: - CoseHeaderIdentifier Tests
    
    @Test func testCoseHeaderIdentifierFromFullName() async throws {
        #expect(CoseHeaderIdentifier.fromFullName("ALG") == .algorithm)
        #expect(CoseHeaderIdentifier.fromFullName("IV") == .iv)
        #expect(CoseHeaderIdentifier.fromFullName("KID") == .kid)
        #expect(CoseHeaderIdentifier.fromFullName("UNKNOWN") == nil)
        #expect(CoseHeaderIdentifier.fromFullName("PARTY_V_OTHER") == .partyVOther)
        #expect(CoseHeaderIdentifier.fromFullName("RESERVED") == .reserved)
        #expect(CoseHeaderIdentifier.fromFullName("CRITICAL") == .critical)
        #expect(CoseHeaderIdentifier.fromFullName("CONTENT_TYPE") == .contentType)
        #expect(CoseHeaderIdentifier.fromFullName("PARTIAL_IV") == .partialIV)
        #expect(CoseHeaderIdentifier.fromFullName("COUNTER_SIGN") == .counterSignature)
        #expect(CoseHeaderIdentifier.fromFullName("COUNTER_SIGN0") == .counterSignature0)
        #expect(CoseHeaderIdentifier.fromFullName("KID_CONTEXT") == .kidContext)
        #expect(CoseHeaderIdentifier.fromFullName("X5_BAG") == .x5bag)
        #expect(CoseHeaderIdentifier.fromFullName("X5_CHAIN") == .x5chain)
        #expect(CoseHeaderIdentifier.fromFullName("X5_T") == .x5t)
        #expect(CoseHeaderIdentifier.fromFullName("X5_U") == .x5u)
        #expect(CoseHeaderIdentifier.fromFullName("EPHEMERAL_KEY") == .ephemeralKey)
        #expect(CoseHeaderIdentifier.fromFullName("STATIC_KEY") == .staticKey)
        #expect(CoseHeaderIdentifier.fromFullName("STATIC_KEY_ID") == .staticKeyID)
        #expect(CoseHeaderIdentifier.fromFullName("SALT") == .salt)
        #expect(CoseHeaderIdentifier.fromFullName("PARTY_U_ID") == .partyUID)
        #expect(CoseHeaderIdentifier.fromFullName("PARTY_U_NONCE") == .partyUNonce)
        #expect(CoseHeaderIdentifier.fromFullName("PARTY_U_OTHER") == .partyUOther)
        #expect(CoseHeaderIdentifier.fromFullName("PARTY_V_ID") == .partyVID)
        #expect(CoseHeaderIdentifier.fromFullName("PARTY_V_NONCE") == .partyVNonce)
        #expect(CoseHeaderIdentifier.fromFullName("SUPP_PUB_OTHER") == .suppPubOther)
        #expect(CoseHeaderIdentifier.fromFullName("SUPP_PRIV_OTHER") == .suppPrivOther)
        #expect(CoseHeaderIdentifier.fromFullName("NOT_A_REAL_VALUE") == nil)
    }
    
    @Test func testCoseHeaderIdentifierRawValue() async throws {
        #expect(CoseHeaderIdentifier(rawValue: 0) == .reserved)
        #expect(CoseHeaderIdentifier(rawValue: 1) == .algorithm)
        #expect(CoseHeaderIdentifier(rawValue: 2) == .critical)
        #expect(CoseHeaderIdentifier(rawValue: 3) == .contentType)
        #expect(CoseHeaderIdentifier(rawValue: 4) == .kid)
        #expect(CoseHeaderIdentifier(rawValue: 5) == .iv)
        #expect(CoseHeaderIdentifier(rawValue: 6) == .partialIV)
        #expect(CoseHeaderIdentifier(rawValue: 7) == .counterSignature)
        #expect(CoseHeaderIdentifier(rawValue: 9) == .counterSignature0)
        #expect(CoseHeaderIdentifier(rawValue: 10) == .kidContext)
        #expect(CoseHeaderIdentifier(rawValue: 32) == .x5bag)
        #expect(CoseHeaderIdentifier(rawValue: 33) == .x5chain)
        #expect(CoseHeaderIdentifier(rawValue: 34) == .x5t)
        #expect(CoseHeaderIdentifier(rawValue: 35) == .x5u)
        #expect(CoseHeaderIdentifier(rawValue: -1) == .ephemeralKey)
        #expect(CoseHeaderIdentifier(rawValue: -2) == .staticKey)
        #expect(CoseHeaderIdentifier(rawValue: -3) == .staticKeyID)
        #expect(CoseHeaderIdentifier(rawValue: -20) == .salt)
        #expect(CoseHeaderIdentifier(rawValue: -21) == .partyUID)
        #expect(CoseHeaderIdentifier(rawValue: -22) == .partyUNonce)
        #expect(CoseHeaderIdentifier(rawValue: -23) == .partyUOther)
        #expect(CoseHeaderIdentifier(rawValue: -24) == .partyVID)
        #expect(CoseHeaderIdentifier(rawValue: -25) == .partyVNonce)
        #expect(CoseHeaderIdentifier(rawValue: -26) == .partyVOther)
        #expect(CoseHeaderIdentifier(rawValue: -998) == .suppPubOther)
        #expect(CoseHeaderIdentifier(rawValue: -999) == .suppPrivOther)
        #expect(CoseHeaderIdentifier(rawValue: 99) == nil)  // Test for an invalid value
    }
    
    // MARK: - CoseHeaderAttribute Tests
    
    @Test func testCoseHeaderAttributeFromIdFail() async throws {
        #expect(throws: CoseError.self) {
            let _ = try CoseHeaderAttribute.fromId(for: [])
        }
        #expect(throws: CoseError.self) {
            let _ = try CoseHeaderAttribute.fromId(for: 99)
        }
        #expect(throws: CoseError.self) {
            let _ = try CoseHeaderAttribute.fromId(for: "NOT_A_REAL_VALUE")
        }
    }
    
    // MARK: - Individual Header Attribute Tests
    @Test func testReservedAttribute() async throws {
        let reserved1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.reserved)
        let reserved2 = try CoseHeaderAttribute.fromId(for: "RESERVED")
        let reserved3 = try CoseHeaderAttribute.fromId(for: 0)
        
        #expect(reserved1 == reserved2)
        #expect(reserved2 == reserved3)
        #expect(reserved1.identifier == CoseHeaderIdentifier.reserved.rawValue)
        #expect(reserved1.fullname == "RESERVED")
    }
    
    @Test func testAlgorithmAttribute() async throws {
        let algorithm1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.algorithm)
        let algorithm2 = try CoseHeaderAttribute.fromId(for: "ALG")
        let algorithm3 = try CoseHeaderAttribute.fromId(for: 1)
        
        #expect(algorithm1 == algorithm2)
        #expect(algorithm2 == algorithm3)
        #expect(algorithm1.identifier == CoseHeaderIdentifier.algorithm.rawValue)
        #expect(algorithm1.fullname == "ALG")
    }
    
    @Test func testCriticalAttribute() async throws {
        let critical1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.critical)
        let critical2 = try CoseHeaderAttribute.fromId(for: "CRITICAL")
        let critical3 = try CoseHeaderAttribute.fromId(for: 2)
        
        #expect(critical1 == critical2)
        #expect(critical2 == critical3)
        #expect(critical1.identifier == CoseHeaderIdentifier.critical.rawValue)
        #expect(critical1.fullname == "CRITICAL")
        #expect(try critical1.valueParser!([1, 2, 3]) as! [Int] == [1, 2, 3])
        
        #expect(throws: CoseError.self) {
            try critical1.valueParser!([])
        }
    }
    
    @Test func testContentTypeValidation() async throws {
        let contentType1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.contentType)
        let contentType2 = try CoseHeaderAttribute.fromId(for: "CONTENT_TYPE")
        let contentType3 = try CoseHeaderAttribute.fromId(for: 3)
        
        #expect(contentType1 == contentType2)
        #expect(contentType3 == contentType3)
        #expect(contentType1.identifier == CoseHeaderIdentifier.contentType.rawValue)
        #expect(contentType1.fullname == "CONTENT_TYPE")
        #expect(try contentType1.valueParser!(10) as! Int == 10)
        #expect(try contentType1.valueParser!("text/plain") as! String == "text/plain")
        
        #expect(throws: CoseError.self) {
            try contentType1.valueParser!(Data())
        }
    }
    
    @Test func testKIDValidation() async throws {
        let kid1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.kid)
        let kid2 = try CoseHeaderAttribute.fromId(for: "KID")
        let kid3 = try CoseHeaderAttribute.fromId(for: 4)
        
        #expect(kid1 == kid2)
        #expect(kid2 == kid3)
        #expect(kid1.identifier == CoseHeaderIdentifier.kid.rawValue)
        #expect(kid1.fullname == "KID")
        #expect(try kid1.valueParser!(Data([0x01, 0x02])) as! Data == Data([0x01, 0x02]))
        
        #expect(throws: CoseError.self) {
            try kid1.valueParser!("")
        }
    }
    
    @Test func testIVValidation() async throws {
        let iv1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.iv)
        let iv2 = try CoseHeaderAttribute.fromId(for: "IV")
        let iv3 = try CoseHeaderAttribute.fromId(for: 5)
        
        #expect(iv1 == iv2)
        #expect(iv2 == iv3)
        #expect(iv1.identifier == CoseHeaderIdentifier.iv.rawValue)
        #expect(iv1.fullname == "IV")
        #expect(try iv1.valueParser!(Data([0x01, 0x02])) as! Data == Data([0x01, 0x02]))
        
        #expect(throws: CoseError.self) {
            try iv1.valueParser!("")
        }
    }
    
    @Test func testPartialIVValidation() async throws {
        let partialIV1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.partialIV)
        let partialIV2 = try CoseHeaderAttribute.fromId(for: "PARTIAL_IV")
        let partialIV3 = try CoseHeaderAttribute.fromId(for: 6)
        
        #expect(partialIV1 == partialIV2)
        #expect(partialIV2 == partialIV3)
        #expect(partialIV1.identifier == CoseHeaderIdentifier.partialIV.rawValue)
        #expect(partialIV1.fullname == "PARTIAL_IV")
        #expect(try partialIV1.valueParser!(Data([0x01, 0x02])) as! Data == Data([0x01, 0x02]))
        
        #expect(throws: CoseError.self) {
            try partialIV1.valueParser!("")
        }
    }
    
    @Test func testCounterSignatureAttribute() async throws {
        let counterSign1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.counterSignature)
        let counterSign2 = try CoseHeaderAttribute.fromId(for: "COUNTER_SIGN")
        let counterSign3 = try CoseHeaderAttribute.fromId(for: 7)
        
        #expect(counterSign1 == counterSign2)
        #expect(counterSign2 == counterSign3)
        #expect(counterSign1.identifier == CoseHeaderIdentifier.counterSignature.rawValue)
        #expect(counterSign1.fullname == "COUNTER_SIGN")
    }

    @Test func testCounterSignature0Attribute() async throws {
        let counterSign01 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.counterSignature0)
        let counterSign02 = try CoseHeaderAttribute.fromId(for: "COUNTER_SIGN0")
        let counterSign03 = try CoseHeaderAttribute.fromId(for: 9)
        
        #expect(counterSign01 == counterSign02)
        #expect(counterSign02 == counterSign03)
        #expect(counterSign01.identifier == CoseHeaderIdentifier.counterSignature0.rawValue)
        #expect(counterSign01.fullname == "COUNTER_SIGN0")
        #expect(try counterSign01.valueParser!(Data([0x01])) as! Data == Data([0x01]))
        
        #expect(throws: CoseError.self) {
            try counterSign01.valueParser!("")
        }
    }

    @Test func testKIDContextAttribute() async throws {
        let kidContext1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.kidContext)
        let kidContext2 = try CoseHeaderAttribute.fromId(for: "KID_CONTEXT")
        let kidContext3 = try CoseHeaderAttribute.fromId(for: 10)
        
        #expect(kidContext1 == kidContext2)
        #expect(kidContext2 == kidContext3)
        #expect(kidContext1.identifier == CoseHeaderIdentifier.kidContext.rawValue)
        #expect(kidContext1.fullname == "KID_CONTEXT")
        #expect(try kidContext1.valueParser!(Data([0x01, 0x02])) as! Data == Data([0x01, 0x02]))
        
        #expect(throws: CoseError.self) {
            try kidContext1.valueParser!("")
        }
    }

    @Test func testX5bagAttribute() async throws {
        let x5bag1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.x5bag)
        let x5bag2 = try CoseHeaderAttribute.fromId(for: "X5_BAG")
        let x5bag3 = try CoseHeaderAttribute.fromId(for: 32)
        
        #expect(x5bag1 == x5bag2)
        #expect(x5bag2 == x5bag3)
        #expect(x5bag1.identifier == CoseHeaderIdentifier.x5bag.rawValue)
        #expect(x5bag1.fullname == "X5_BAG")
    }

    @Test func testX5chainAttribute() async throws {
        let x5chain1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.x5chain)
        let x5chain2 = try CoseHeaderAttribute.fromId(for: "X5_CHAIN")
        let x5chain3 = try CoseHeaderAttribute.fromId(for: 33)
        
        #expect(x5chain1 == x5chain2)
        #expect(x5chain2 == x5chain3)
        #expect(x5chain1.identifier == CoseHeaderIdentifier.x5chain.rawValue)
        #expect(x5chain1.fullname == "X5_CHAIN")
    }

    @Test func testX5tAttribute() async throws {
        let x5t1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.x5t)
        let x5t2 = try CoseHeaderAttribute.fromId(for: "X5_T")
        let x5t3 = try CoseHeaderAttribute.fromId(for: 34)
        
        #expect(x5t1 == x5t2)
        #expect(x5t2 == x5t3)
        #expect(x5t1.identifier == CoseHeaderIdentifier.x5t.rawValue)
        #expect(x5t1.fullname == "X5_T")
    }

    @Test func testX5uAttribute() async throws {
        let x5u1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.x5u)
        let x5u2 = try CoseHeaderAttribute.fromId(for: "X5_U")
        let x5u3 = try CoseHeaderAttribute.fromId(for: 35)
        
        #expect(x5u1 == x5u2)
        #expect(x5u2 == x5u3)
        #expect(x5u1.identifier == CoseHeaderIdentifier.x5u.rawValue)
        #expect(x5u1.fullname == "X5_U")
    }
    
    @Test func testEphemeralKeyAttribute() async throws {
        let ephemeralKey1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.ephemeralKey)
        let ephemeralKey2 = try CoseHeaderAttribute.fromId(for: "EPHEMERAL_KEY")
        let ephemeralKey3 = try CoseHeaderAttribute.fromId(for: -1)
        
        #expect(ephemeralKey1 == ephemeralKey2)
        #expect(ephemeralKey2 == ephemeralKey3)
        #expect(ephemeralKey1.identifier == CoseHeaderIdentifier.ephemeralKey.rawValue)
        #expect(ephemeralKey1.fullname == "EPHEMERAL_KEY")
    }

    @Test func testStaticKeyAttribute() async throws {
        let staticKey1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.staticKey)
        let staticKey2 = try CoseHeaderAttribute.fromId(for: "STATIC_KEY")
        let staticKey3 = try CoseHeaderAttribute.fromId(for: -2)
        
        #expect(staticKey1 == staticKey2)
        #expect(staticKey2 == staticKey3)
        #expect(staticKey1.identifier == CoseHeaderIdentifier.staticKey.rawValue)
        #expect(staticKey1.fullname == "STATIC_KEY")
    }

    @Test func testStaticKeyIDAttribute() async throws {
        let staticKeyID1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.staticKeyID)
        let staticKeyID2 = try CoseHeaderAttribute.fromId(for: "STATIC_KEY_ID")
        let staticKeyID3 = try CoseHeaderAttribute.fromId(for: -3)
        
        #expect(staticKeyID1 == staticKeyID2)
        #expect(staticKeyID2 == staticKeyID3)
        #expect(staticKeyID1.identifier == CoseHeaderIdentifier.staticKeyID.rawValue)
        #expect(staticKeyID1.fullname == "STATIC_KEY_ID")
    }

    @Test func testSaltAttribute() async throws {
        let salt1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.salt)
        let salt2 = try CoseHeaderAttribute.fromId(for: "SALT")
        let salt3 = try CoseHeaderAttribute.fromId(for: -20)
        
        #expect(salt1 == salt2)
        #expect(salt2 == salt3)
        #expect(salt1.identifier == CoseHeaderIdentifier.salt.rawValue)
        #expect(salt1.fullname == "SALT")
    }

    @Test func testPartyUIDAttribute() async throws {
        let partyUID1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.partyUID)
        let partyUID2 = try CoseHeaderAttribute.fromId(for: "PARTY_U_ID")
        let partyUID3 = try CoseHeaderAttribute.fromId(for: -21)
        
        #expect(partyUID1 == partyUID2)
        #expect(partyUID2 == partyUID3)
        #expect(partyUID1.identifier == CoseHeaderIdentifier.partyUID.rawValue)
        #expect(partyUID1.fullname == "PARTY_U_ID")
    }

    @Test func testPartyUNonceAttribute() async throws {
        let partyUNonce1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.partyUNonce)
        let partyUNonce2 = try CoseHeaderAttribute.fromId(for: "PARTY_U_NONCE")
        let partyUNonce3 = try CoseHeaderAttribute.fromId(for: -22)
        
        #expect(partyUNonce1 == partyUNonce2)
        #expect(partyUNonce2 == partyUNonce3)
        #expect(partyUNonce1.identifier == CoseHeaderIdentifier.partyUNonce.rawValue)
        #expect(partyUNonce1.fullname == "PARTY_U_NONCE")
    }

    @Test func testPartyUOtherAttribute() async throws {
        let partyUOther1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.partyUOther)
        let partyUOther2 = try CoseHeaderAttribute.fromId(for: "PARTY_U_OTHER")
        let partyUOther3 = try CoseHeaderAttribute.fromId(for: -23)
        
        #expect(partyUOther1 == partyUOther2)
        #expect(partyUOther2 == partyUOther3)
        #expect(partyUOther1.identifier == CoseHeaderIdentifier.partyUOther.rawValue)
        #expect(partyUOther1.fullname == "PARTY_U_OTHER")
    }

    @Test func testPartyVIDAttribute() async throws {
        let partyVID1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.partyVID)
        let partyVID2 = try CoseHeaderAttribute.fromId(for: "PARTY_V_ID")
        let partyVID3 = try CoseHeaderAttribute.fromId(for: -24)
        
        #expect(partyVID1 == partyVID2)
        #expect(partyVID2 == partyVID3)
        #expect(partyVID1.identifier == CoseHeaderIdentifier.partyVID.rawValue)
        #expect(partyVID1.fullname == "PARTY_V_ID")
    }

    @Test func testPartyVNonceAttribute() async throws {
        let partyVNonce1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.partyVNonce)
        let partyVNonce2 = try CoseHeaderAttribute.fromId(for: "PARTY_V_NONCE")
        let partyVNonce3 = try CoseHeaderAttribute.fromId(for: -25)
        
        #expect(partyVNonce1 == partyVNonce2)
        #expect(partyVNonce2 == partyVNonce3)
        #expect(partyVNonce1.identifier == CoseHeaderIdentifier.partyVNonce.rawValue)
        #expect(partyVNonce1.fullname == "PARTY_V_NONCE")
    }
    
    @Test func testPartyVOtherAttribute() async throws {
        let partyVOther1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.partyVOther)
        let partyVOther2 = try CoseHeaderAttribute.fromId(for: "PARTY_V_OTHER")
        let partyVOther3 = try CoseHeaderAttribute.fromId(for: -26)
        
        #expect(partyVOther1 == partyVOther2)
        #expect(partyVOther2 == partyVOther3)
        #expect(partyVOther1.identifier == CoseHeaderIdentifier.partyVOther.rawValue)
        #expect(partyVOther1.fullname == "PARTY_V_OTHER")
    }

    @Test func testSuppPubOtherAttribute() async throws {
        let suppPubOther1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.suppPubOther)
        let suppPubOther2 = try CoseHeaderAttribute.fromId(for: "SUPP_PUB_OTHER")
        let suppPubOther3 = try CoseHeaderAttribute.fromId(for: -998)
        
        #expect(suppPubOther1 == suppPubOther2)
        #expect(suppPubOther2 == suppPubOther3)
        #expect(suppPubOther1.identifier == CoseHeaderIdentifier.suppPubOther.rawValue)
        #expect(suppPubOther1.fullname == "SUPP_PUB_OTHER")
    }

    @Test func testSuppPrivOtherAttribute() async throws {
        let suppPrivOther1 = try CoseHeaderAttribute.fromId(for: CoseHeaderIdentifier.suppPrivOther)
        let suppPrivOther2 = try CoseHeaderAttribute.fromId(for: "SUPP_PRIV_OTHER")
        let suppPrivOther3 = try CoseHeaderAttribute.fromId(for: -999)
        
        #expect(suppPrivOther1 == suppPrivOther2)
        #expect(suppPrivOther2 == suppPrivOther3)
        #expect(suppPrivOther1.identifier == CoseHeaderIdentifier.suppPrivOther.rawValue)
        #expect(suppPrivOther1.fullname == "SUPP_PRIV_OTHER")
    }
    
    // MARK: - Utility Function Tests
    
    @Test func testIsBstrFunction() async throws {
        #expect(try isBstr(Data([0x01, 0x02])) as! Data == Data([0x01, 0x02]))
        
        #expect(throws: CoseError.self) {
            try isBstr("")
        }
    }
    
    @Test func testCritIsArrayFunction() async throws {
        #expect(try critIsArray([1, 2]) as! [Int] == [1, 2])
        #expect(try critIsArray(["A", "B"]) as! [String] == ["A", "B"])
        
        #expect(throws: CoseError.self) {
            try critIsArray([])
        }
    }
    
    @Test func testContentTypeIsUIntOrTstrFunction() async throws {
        #expect(try contentTypeIsUIntOrTstr(42) as! Int == 42)
        #expect(try contentTypeIsUIntOrTstr("application/json") as! String == "application/json")
        
        #expect(throws: CoseError.self) {
            try contentTypeIsUIntOrTstr(Data())
        }
    }
}
