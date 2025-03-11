import Testing
@testable import SwiftCOSE

struct KTYTests {
    
    // MARK: - Individual KTY Tests
    @Test("Test All KTY", arguments: KeyTypeIdentifier.allCases)
    func testKTY(_ ktyId: KeyTypeIdentifier) async throws {
        let kty1 = try KTY.fromId(for: ktyId)
        let kty2 = try KTY.fromId(for: kty1.fullname!)
        let kty3 = try KTY.fromId(for: ktyId.rawValue)
        
        #expect(kty1 == kty2)
        #expect(kty2 == kty3)
        #expect(kty1.identifier == ktyId.rawValue)
        #expect(kty1.identifier == KeyTypeIdentifier.fromFullName(kty1.fullname!)?.rawValue)
    }
}
