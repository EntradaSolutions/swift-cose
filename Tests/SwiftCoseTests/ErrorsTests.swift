import XCTest
@testable import SwiftCose

final class CoseErrorTests: XCTestCase {
    
    func testGenericException() {
        let errorMessage = "A generic error occurred"
        let error = CoseError.genericError(errorMessage)
        
        switch error {
        case .genericError(let message):
            XCTAssertEqual(message, errorMessage, "The generic exception message should match the provided string.")
        default:
            XCTFail("Expected .genericException case.")
        }
    }
    
    func testIllegalAlgorithm() {
        let errorMessage = "Algorithm not supported"
        let error = CoseError.invalidAlgorithm(errorMessage)
        
        switch error {
        case .invalidAlgorithm(let message):
            XCTAssertEqual(message, errorMessage, "The illegal algorithm message should match the provided string.")
        default:
            XCTFail("Expected .illegalAlgorithm case.")
        }
    }
    
    func testIllegalKeyOps() {
        let errorMessage = "Invalid key operations"
        let error = CoseError.invalidKeyOps(errorMessage)
        
        switch error {
        case .invalidKeyOps(let message):
            XCTAssertEqual(message, errorMessage, "The illegal key operations message should match the provided string.")
        default:
            XCTFail("Expected .illegalKeyOps case.")
        }
    }
    
    func testIllegalKeyType() {
        let errorMessage = "Invalid key type"
        let error = CoseError.invalidKeyType(errorMessage)
        
        switch error {
        case .invalidKeyType(let message):
            XCTAssertEqual(message, errorMessage, "The illegal key type message should match the provided string.")
        default:
            XCTFail("Expected .illegalKeyType case.")
        }
    }
    
    func testInvalidKey() {
        let errorMessage = "Key is not valid"
        let error = CoseError.invalidKey(errorMessage)
        
        switch error {
        case .invalidKey(let message):
            XCTAssertEqual(message, errorMessage, "The invalid key message should match the provided string.")
        default:
            XCTFail("Expected .invalidKey case.")
        }
    }
    
    func testInvalidKIDValue() {
        let errorMessage = "KID value is not valid"
        let error = CoseError.invalidKIDValue(errorMessage)
        
        switch error {
        case .invalidKIDValue(let message):
            XCTAssertEqual(message, errorMessage, "The invalid KID value message should match the provided string.")
        default:
            XCTFail("Expected .invalidKIDValue case.")
        }
    }
    
    func testInvalidCriticalValue() {
        let errorMessage = "Critical value is not valid"
        let error = CoseError.invalidCriticalValue(errorMessage)
        
        switch error {
        case .invalidCriticalValue(let message):
            XCTAssertEqual(message, errorMessage, "The invalid critical value message should match the provided string.")
        default:
            XCTFail("Expected .invalidCriticalValue case.")
        }
    }
    
    func testInvalidContentType() {
        let errorMessage = "Content type is invalid"
        let error = CoseError.invalidContentType(errorMessage)
        
        switch error {
        case .invalidContentType(let message):
            XCTAssertEqual(message, errorMessage, "The invalid content type message should match the provided string.")
        default:
            XCTFail("Expected .invalidContentType case.")
        }
    }
    
    func testMalformedMessage() {
        let errorMessage = "Message is malformed"
        let error = CoseError.malformedMessage(errorMessage)
        
        switch error {
        case .malformedMessage(let message):
            XCTAssertEqual(message, errorMessage, "The malformed message error should match the provided string.")
        default:
            XCTFail("Expected .malformedMessage case.")
        }
    }
    
    func testUnknownAttribute() {
        let errorMessage = "Unknown attribute found"
        let error = CoseError.unknownAttribute(errorMessage)
        
        switch error {
        case .unknownAttribute(let message):
            XCTAssertEqual(message, errorMessage, "The unknown attribute error should match the provided string.")
        default:
            XCTFail("Expected .unknownAttribute case.")
        }
    }
    
    func testUnsupportedCurve() {
        let errorMessage = "Curve is not supported"
        let error = CoseError.unsupportedCurve(errorMessage)
        
        switch error {
        case .unsupportedCurve(let message):
            XCTAssertEqual(message, errorMessage, "The unsupported curve error should match the provided string.")
        default:
            XCTFail("Expected .unsupportedCurve case.")
        }
    }
}
