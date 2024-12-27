import Testing
import Foundation
import UncommonCrypto
import CryptoKit
import K1
@testable import SwiftCose

struct CurveTypeTests {
    // Test that all cases are covered
    @Test func testCurveTypeCaseCount() async throws {
        #expect(CurveType.allCases.count == 8)
    }
    
    @Test func testKeyTypeCaseCount() async throws {
        #expect(KeyType.allCases.count == 3)
    }
    
    // Test raw values of CurveType
    @Test func testCurveTypeRawValues() async throws {
        #expect(CurveType.SECP256K1 != nil)
        #expect(CurveType.SECP256R1 != nil)
        #expect(CurveType.SECP384R1 != nil)
        #expect(CurveType.SECP521R1 != nil)
        #expect(CurveType.ED25519 != nil)
        #expect(CurveType.ED448 != nil)
        #expect(CurveType.X25519 != nil)
        #expect(CurveType.X448 != nil)
    }
    
    // Test raw values of KeyType
    @Test func testKeyTypeRawValues() async throws {
        #expect(KeyType.ktyEC2 != nil)
        #expect(KeyType.ktyOKP != nil)
        #expect(KeyType.none != nil)
    }
    
    // MARK: - Individual CoseCurve Tests
    @Test("Test All Cose Curves", arguments: CoseCurveIdentifier.allCases)
    func testCoseCurve(_ curveId: CoseCurveIdentifier) async throws {
        let curve1 = try CoseCurve.fromId(for: curveId)
        let curve2 = try CoseCurve.fromId(for: curve1.fullname)
        let curve3 = try CoseCurve.fromId(for: curveId.rawValue)
        
        #expect(curve1 == curve2)
        #expect(curve2 == curve3)
        #expect(curve1.identifier == curveId.rawValue)
        #expect(curve1.identifier == CoseCurveIdentifier.fromFullName(curve1.fullname)?.rawValue)
    }
    
    
}
