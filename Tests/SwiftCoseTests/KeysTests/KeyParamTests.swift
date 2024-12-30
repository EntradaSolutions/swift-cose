import Testing
@testable import SwiftCose

struct KeyParamTests {
    
    // MARK: - Individual KeyParam Tests
    @Test("Test All KeyParam", arguments: KeyParamIdentifier.allCases)
    func testKeyParam(_ keyParamId: KeyParamIdentifier) async throws {
        let keyParam1 = try KeyParam.fromId(for: keyParamId)
        let keyParam2 = try KeyParam.fromId(for: keyParam1.fullname)
        let keyParam3 = try KeyParam.fromId(for: keyParamId.rawValue)
        
        #expect(keyParam1 == keyParam2)
        #expect(keyParam2 == keyParam3)
        #expect(keyParam1.identifier == keyParamId.rawValue)
        #expect(keyParam1.identifier == KeyParamIdentifier.fromFullName(keyParam1.fullname)?.rawValue)
    }
    
    // MARK: - Individual EC2KeyParam Tests
    @Test("Test All EC2KeyParam", arguments: EC2KeyParamIdentifier.allCases)
    func testEC2KeyParam(_ keyParamId: EC2KeyParamIdentifier) async throws {
        let keyParam1 = try EC2KeyParam.fromId(for: keyParamId)
        let keyParam2 = try EC2KeyParam.fromId(for: keyParam1.fullname)
        let keyParam3 = try EC2KeyParam.fromId(for: keyParamId.rawValue)
        
        #expect(keyParam1 == keyParam2)
        #expect(keyParam2 == keyParam3)
        #expect(keyParam1.identifier == keyParamId.rawValue)
        #expect(keyParam1.identifier == EC2KeyParamIdentifier.fromFullName(keyParam1.fullname)?.rawValue)
    }
    
    // MARK: - Individual OKPKeyParam Tests
    @Test("Test All OKPKeyParam", arguments: OKPKeyParamIdentifier.allCases)
    func testOKPKeyParam(_ keyParamId: OKPKeyParamIdentifier) async throws {
        let keyParam1 = try OKPKeyParam.fromId(for: keyParamId)
        let keyParam2 = try OKPKeyParam.fromId(for: keyParam1.fullname)
        let keyParam3 = try OKPKeyParam.fromId(for: keyParamId.rawValue)
        
        #expect(keyParam1 == keyParam2)
        #expect(keyParam2 == keyParam3)
        #expect(keyParam1.identifier == keyParamId.rawValue)
        #expect(keyParam1.identifier == OKPKeyParamIdentifier.fromFullName(keyParam1.fullname)?.rawValue)
    }
    
    // MARK: - Individual RSAKeyParam Tests
    @Test("Test All RSAKeyParam", arguments: RSAKeyParamIdentifier.allCases)
    func testRSAKeyParam(_ keyParamId: RSAKeyParamIdentifier) async throws {
        let keyParam1 = try RSAKeyParam.fromId(for: keyParamId)
        let keyParam2 = try RSAKeyParam.fromId(for: keyParam1.fullname)
        let keyParam3 = try RSAKeyParam.fromId(for: keyParamId.rawValue)
        
        #expect(keyParam1 == keyParam2)
        #expect(keyParam2 == keyParam3)
        #expect(keyParam1.identifier == keyParamId.rawValue)
        #expect(keyParam1.identifier == RSAKeyParamIdentifier.fromFullName(keyParam1.fullname)?.rawValue)
    }
    
    // MARK: - Individual SymmetricKeyParam Tests
    @Test("Test All SymmetricKeyParam", arguments: SymmetricKeyParamIdentifier.allCases)
    func testSymmetricKeyParam(_ keyParamId: SymmetricKeyParamIdentifier) async throws {
        let keyParam1 = try SymmetricKeyParam.fromId(for: keyParamId)
        let keyParam2 = try SymmetricKeyParam.fromId(for: keyParam1.fullname)
        let keyParam3 = try SymmetricKeyParam.fromId(for: keyParamId.rawValue)
        
        #expect(keyParam1 == keyParam2)
        #expect(keyParam2 == keyParam3)
        #expect(keyParam1.identifier == keyParamId.rawValue)
        #expect(keyParam1.identifier == SymmetricKeyParamIdentifier.fromFullName(keyParam1.fullname)?.rawValue)
    }
}
