import Foundation
import PotentCBOR


/// Base class for COSE attributes
public class CoseAttribute: Comparable {
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
        self.valueParser = valueParser
    }

    /// The description of the attribute
    public var description: String {
        return "<\(fullname): \(identifier)>"
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
}

// MARK: - Data Extensions
extension Data {
    var toBytes: [UInt8] {
        return [UInt8](self)
    }
    
    var toHex: String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
    
    var toCBOR: CBOR {
        return try! CBORSerialization.cbor(from: self)
    }
    
    func toInt() -> Int {
        return reduce(0) { ($0 << 8) | Int($1) }
    }

    static func fromInt(_ value: Int, length: Int) -> Data {
        var num = value
        var data = Data()
        for _ in 0..<length {
            data.insert(UInt8(num & 0xff), at: 0)
            num >>= 8
        }
        return data
    }
}

// MARK: - Int Extensions
extension Int {
    func toData() -> Data {
        var value = self
        return withUnsafeBytes(of: &value) { Data($0) }
    }
}

// MARK: - Array Extensions
extension Array where Element == UInt8 {
    var toData: Data {
        return Data(self)
    }
}

// MARK: - String Extensions
extension String {
    var hexStringToData: Data? {
        var data = Data()
        var tempHex = self
        
        // Ensure string length is even
        if tempHex.count % 2 != 0 {
            tempHex = "0" + tempHex
        }
        
        // Iterate through the string in pairs of two
        var index = tempHex.startIndex
        while index < tempHex.endIndex {
            let nextIndex = tempHex.index(index, offsetBy: 2)
            let byteString = tempHex[index..<nextIndex]
            if let byte = UInt8(byteString, radix: 16) {
                data.append(byte)
            } else {
                return nil // Invalid hex string
            }
            index = nextIndex
        }
        return data
    }
}

// MARK: - Dictionary Extensions
extension Dictionary where Key == String, Value == Any {
    func mapKeysToCbor() -> OrderedDictionary<CBOR, CBOR> {
        return self.reduce(into: [:]) { result, element in
            result[CBOR(element.key)] = CBOR.fromAny(element.value)
        }
    }
}

// MARK: - Dictionary Extensions
extension CBOR {
    static func fromAny(_ value: Any) -> CBOR {
        if let stringValue = value as? String {
            return .utf8String(stringValue)
        } else if let intValue = value as? Int {
            return .unsignedInt(UInt64(intValue))
        } else if let dataValue = value as? Data {
            return .byteString(dataValue)
        } else if let dictValue = value as? [String: Any] {
            return .map(dictValue.mapKeysToCbor())
        } else {
            return .null
        }
    }
}
