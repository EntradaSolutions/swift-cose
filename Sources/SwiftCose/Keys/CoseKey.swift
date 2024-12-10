import Foundation
import PotentCBOR

public enum CoseKeyType: String, Codable {
    case EC2 = "EC2"
    
}

public class CoseKey {
    public var store: [String: CoseKey] = [:]
    private var keyTypes: [String: CoseKey] = [:]
    private var key: CoseKey?
    
    // MARK: - Initialization
    init(keyDict: [String: CoseKey]) {
        self.store = keyDict
        if keyDict["KpKeyOps"] != nil {
            self.store.removeValue(forKey: "KpKeyOps")
        }
    }
    
    // MARK: - Base64 Encoding/Decoding
    static func base64decode(_ input: String) -> Data? {
        var normalizedInput = input.replacingOccurrences(of: "-", with: "+")
                                   .replacingOccurrences(of: "_", with: "/")
        switch normalizedInput.count % 4 {
        case 0:
            break
        case 2:
            normalizedInput += "=="
        case 3:
            normalizedInput += "="
        default:
            return nil
        }
        return Data(base64Encoded: normalizedInput)
    }
    
    static func base64encode(_ data: Data) -> String {
        return data.base64EncodedString()
    }
    
    // MARK: - Encode and Decode
    public func encode() -> Data? {
        return try CBORSerialization.data(from: store)
    }
    
    public static func decode(_ cborData: Data) throws -> CoseKey? {
        let cbor = try CBORSerialization.cbor(from: cborData)
        return fromCBOR(cbor: cbor)
    }
    
    public class func fromCBOR(cbor: CBOR) -> CoseKey? {
        guard let map = cbor.mapValue else {
            return nil
        }

        if let keyTypeValue = map[CBOR("KpKty")]?.utf8StringValue,
           let keyTypeClass = keyTypes[keyTypeValue] {
            return keyTypeClass.init(keyDict: map.unwrapped as? [String: Any] ?? [:])
        } else if let keyTypeIdentifier = map[CBOR("KpKty.identifier")]?.utf8StringValue,
                  let keyTypeClass = _keyTypes[keyTypeIdentifier] {
                  let keyTypeClass = _keyTypes[keyTypeIdentifier] {
            return keyTypeClass.init(keyDict: map.unwrapped as? [String: Any] ?? [:])
        } else if let keyTypeFullname = map[CBOR("KpKty.fullname")]?.utf8StringValue,
                  let keyTypeClass = _keyTypes[keyTypeFullname] {
            return keyTypeClass.init(keyDict: map.unwrapped as? [String: Any] ?? [:])
        } else {
            // Replace CoseException with your specific exception if needed
            throw CoseError.invalidKeyType("Invalid key type")
        }
    }
    
    // MARK: - Subscripts
    subscript(key: String) -> Any? {
        get { return store[key] }
        set { store[key] = newValue }
    }
    
    // MARK: - Key Operations
    public var keyOps: [String] {
        get {
            return store["KpKeyOps"] as? [String] ?? []
        }
        set {
            store["KpKeyOps"] = newValue
        }
    }
    
    // MARK: - Key Attributes
    public var kty: String? {
        get {
            return store["KpKty"] as? String
        }
        set {
            store["KpKty"] = newValue
        }
    }
    
    public var alg: String? {
        get {
            return store["KpAlg"] as? String
        }
        set {
            store["KpAlg"] = newValue
        }
    }
    
    public var kid: Data? {
        get {
            return store["KpKid"] as? Data
        }
        set {
            store["KpKid"] = newValue
        }
    }
    
    public var baseIv: Data? {
        get {
            return store["KpBaseIV"] as? Data
        }
        set {
            store["KpBaseIV"] = newValue
        }
    }
    
    // MARK: - Verification
    public func verify(keyType: CoseKey.Type, algorithm: String, keyOps: [String]) throws {
        guard type(of: self) == keyType else {
            throw CoseException.invalidKeyType
        }
        
        if let alg = self.alg, alg != algorithm {
            throw CoseException.illegalAlgorithm
        }
        
        let supportedOps = Set(self.keyOps)
        let requestedOps = Set(keyOps)
        if !requestedOps.isSubset(of: supportedOps) {
            throw CoseException.illegalKeyOps
        }
    }
    
    // MARK: - Helper Methods
    public class func transformKey(_ key: Any, allowUnknownAttrs: Bool = false) -> Any {
        return key // Implement key transformation logic here
    }
}
