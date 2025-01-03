import Foundation
import CryptoSwift
import OrderedCollections
import PotentCodables

public func describe(_ value: Any) -> String {
    return String(describing: value)
}

/// Helper function to truncate a string to a maximum length
/// - Parameters:
///   - input: The input string
///   - maxLength: The maximum length
/// - Returns: The truncated string
public func truncate(_ input: String, maxLength: Int = 10) -> String {
    return input.count > maxLength ? String(input.prefix(maxLength)) + "..." : input
}

/// Convert an integer to a big-endian byte string
/// - Parameter dec: The integer to convert
/// - Returns: The byte string
func toBstr(_ dec: BigUInteger) -> Data {
    guard dec >= 0 else {
        fatalError("Negative values are not supported")
    }
    
    // Calculate the number of bytes needed to represent the integer
    let byteLength = (dec.bitWidth + 7) / 8
    
    // Convert the BigUInteger to big-endian bytes
    let value = dec
    var data = Data(count: byteLength)
    for i in 0..<byteLength {
        let byte = UInt8((value >> ((byteLength - i - 1) * 8)) & 0xFF)
        data[i] = byte
    }
    return data
}

/// Base class for COSE attributes
public class CoseAttribute: Comparable, Hashable, CustomStringConvertible, CustomDebugStringConvertible {
    
//    enum CodingKeys: String, CodingKey {
//        case identifier
//        case fullname
//    }
    
    public var debugDescription: String {
        return description
    }

    public var identifier: Int
    public var fullname: String
    public var valueParser: ((Any) throws -> Any)? = nil
    
    /// Initialize a new COSE attribute
    /// - Parameters:
    ///   - identifier: The identifier of the attribute
    ///   - fullname: The full name of the attribute
    ///   - valueParser: The parser function to convert the attribute value
    public init(
        identifier: Int,
        fullname: String,
        valueParser: ((Any) throws -> Any)? = nil
    ) {
        self.identifier = identifier
        self.fullname = fullname.uppercased()
        self.valueParser = valueParser ?? defaultParser
    }

    /// The description of the attribute
    public var description: String {
        return "<\(fullname): \(identifier)>"
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(identifier)
        hasher.combine(fullname)
    }

    public static func == (lhs: CoseAttribute, rhs: CoseAttribute) -> Bool {
        return lhs.identifier == rhs.identifier
    }

    public static func < (lhs: CoseAttribute, rhs: CoseAttribute) -> Bool {
        return lhs.identifier < rhs.identifier
    }

    public static func > (lhs: CoseAttribute, rhs: CoseAttribute) -> Bool {
        return lhs.identifier > rhs.identifier
    }

    public static func <= (lhs: CoseAttribute, rhs: CoseAttribute) -> Bool {
        return lhs.identifier <= rhs.identifier
    }

    public static func >= (lhs: CoseAttribute, rhs: CoseAttribute) -> Bool {
        return lhs.identifier >= rhs.identifier
    }
    
    public func defaultParser(value: Any) throws -> Any {
        return value
    }
    
//    // MARK: - Codable Protocol
//    required public init(from decoder: Decoder) throws {
//        let container = try decoder.container(keyedBy: CodingKeys.self)
//        self.identifier = try container.decode(Int.self, forKey: .identifier)
//        self.fullname = try container.decode(String.self, forKey: .fullname)
//    }
//    
//    public func encode(to encoder: Encoder) throws {
//        var container = encoder.container(keyedBy: CodingKeys.self)
//        try container.encode(identifier, forKey: .identifier)
////        try container.encode(fullname, forKey: .fullname)
//    }
}
