import Foundation

import Foundation

/// `CoseError` is an enumeration of errors that can be thrown by the COSE library.
enum CoseError: Error {
    case genericError(String)
    case illegalAlgorithm(String)
    case illegalCurve(String)
    case illegalKeyOps(String)
    case illegalKeyType(String)
    case invalidAlgorithm(String)
    case invalidCertificate(String)
    case invalidKey(String)
    case invalidKIDValue(String)
    case invalidCriticalValue(String)
    case invalidContentType(String)
    case invalidHeader(String)
    case invalidMessage(String)
    case malformedMessage(String)
    case unknownAttribute(String)
    case unsupportedCurve(String)
    case valueError(String)
}
