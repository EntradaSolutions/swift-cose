import Testing
@testable import SwiftCose

struct KeyOpsTests {
    
    // MARK: - Individual KeyOps Tests
    @Test("Test All KeyOps", arguments: KeyOpsIdentifier.allCases)
    func testKeyOps(_ keyOpsId: KeyOpsIdentifier) async throws {
        let keyOps1 = try KeyOps.fromId(for: keyOpsId)
        let keyOps2 = try KeyOps.fromId(for: keyOps1.fullname)
        let keyOps3 = try KeyOps.fromId(for: keyOpsId.rawValue)
        
        #expect(keyOps1 == keyOps2)
        #expect(keyOps2 == keyOps3)
        #expect(keyOps1.identifier == keyOpsId.rawValue)
        #expect(keyOps1.identifier == KeyOpsIdentifier.fromFullName(keyOps1.fullname)?.rawValue)
    }
}
