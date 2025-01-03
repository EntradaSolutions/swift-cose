import Testing
import Foundation
import CryptoSwift
@testable import SwiftCOSE

struct UtilsTests {

    // MARK: - toBstr Tests
    @Test
    func testToBstrPositiveInteger() async throws {
        let value = BigUInteger(123456789)
        let result = toBstr(value)
        
        let expectedData = Data([0x07, 0x5B, 0xCD, 0x15])
        #expect(result == expectedData)
    }
    
    @Test
    func testToBstrSmallInteger() async throws {
        let value = BigUInteger(1)
        let result = toBstr(value)
        
        let expectedData = Data([0x01])
        #expect(result == expectedData)
    }
    
    @Test
    func testToBstrEdgeCase() async throws {
        let value = BigUInteger(255)  // Maximum value for one byte
        let result = toBstr(value)
        
        let expectedData = Data([0xFF])
        #expect(result == expectedData)
    }
    
    // MARK: - Truncate Tests
    @Test
    func testTruncateStringShorterThanMax() async throws {
        let input = "Hello"
        let result = truncate(input, maxLength: 10)
        
        #expect(result == "Hello")
    }
    
    @Test
    func testTruncateStringEqualToMax() async throws {
        let input = "HelloWorld"
        let result = truncate(input, maxLength: 10)
        
        #expect(result == "HelloWorld")
    }
    
    @Test
    func testTruncateStringLongerThanMax() async throws {
        let input = "HelloWorldExtended"
        let result = truncate(input, maxLength: 10)
        
        #expect(result == "HelloWorld...")
    }
    
    // MARK: - Describe Tests
    @Test
    func testDescribeSimpleString() async throws {
        let value = "Test"
        let result = describe(value)
        
        #expect(result == "Test")
    }
    
    @Test
    func testDescribeInteger() async throws {
        let value = 123
        let result = describe(value)
        
        #expect(result == "123")
    }
    
    @Test
    func testDescribeComplexObject() async throws {
        struct Sample {
            let name: String
        }
        let obj = Sample(name: "John")
        let result = describe(obj)
        
        #expect(result.contains("Sample(name: \"John\")"))
    }
}
