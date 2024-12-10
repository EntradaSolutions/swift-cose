import Foundation


public class CoseSymmetricKey: CoseKey {
    
    // Mandatory SymKpK attribute (key)
    public var k: Data {
        get {
            guard let key = store["SymKpK"] as? Data else {
                fatalError("Symmetric COSE key must have the SymKpK attribute")
            }
            return key
        }
        set {
            guard newValue.count == 16 || newValue.count == 24 || newValue.count == 32 else {
                fatalError("Key length should be either 16, 24, or 32 bytes")
            }
            store["SymKpK"] = newValue
        }
    }

    // Supported key operations
    public var keyOps: [String] {
        get {
            return store["KpKeyOps"] as? [String] ?? []
        }
        set {
            let supportedOps: Set<String> = ["MAC_CREATE", "MAC_VERIFY", "ENCRYPT", "DECRYPT", "UNWRAP", "WRAP"]
            for op in newValue {
                guard supportedOps.contains(op) else {
                    fatalError("Invalid COSE key operation \(op) for key type SymmetricKey")
                }
            }
            store["KpKeyOps"] = newValue
        }
    }
    
    // Initializer
    public init(k: Data, optionalParams: [String: Any]? = nil) throws {
        guard k.count == 16 || k.count == 24 || k.count == 32 else {
            throw CoseError.invalidKey("Key length should be either 16, 24, or 32 bytes")
        }
        self.k = k
        
        if let optionalParams = optionalParams {
            for (key, value) in optionalParams {
                store[key] = value
            }
        }
        store["KpKty"] = "Symmetric"
    }
    
    // Generate random Symmetric Key
    public static func generateKey(keyLen: Int, optionalParams: [String: Any]? = nil) throws -> SymmetricKey {
        guard keyLen == 16 || keyLen == 24 || keyLen == 32 else {
            throw CoseError.invalidKey("Key length must be 16, 24, or 32 bytes")
        }
        let keyData = Data((0..<keyLen).map { _ in UInt8.random(in: 0...255) })
        return try SymmetricKey(k: keyData, optionalParams: optionalParams)
    }
    
    // Representation
    public override var description: String {
        var keyAttributes = store
        if let key = keyAttributes["SymKpK"] as? Data {
            keyAttributes["SymKpK"] = "<truncated>"
        }
        return "<COSE_Key(Symmetric): \(keyAttributes)>"
    }
}
