import Foundation
import PotentCodables
import PotentCBOR
import OrderedCollections

public struct PartyInfo {
    var identity: Data? = nil
    var nonce: Data? = nil
    var other: Data? = nil

    func encode() -> [CBOR] {
        return [
            identity!.toCBOR,
            nonce?.toCBOR ?? CBOR.null,
            other?.toCBOR ?? CBOR.null
        ]
    }
}

public struct SuppPubInfo {
    private var _keyDataLength: Int
    var protected: Dictionary<AnyHashable, Any> = [:]
    var other: Data = Data()
    
    /// The length of the derived key in bytes.
    /// Set the length of the derived key. Must be of length 16, 24 or 32 bytes.
    var keyDataLength: Int  {
        get {
            return _keyDataLength
        }
        set {
            guard [16, 24, 32].contains(newValue) else {
                fatalError("Not a valid key length: \(newValue)")
            }
            _keyDataLength = newValue
        }
    }

    init(keyDataLength: Int, protected: Dictionary<AnyHashable, Any> = [:], other: Data = Data()) {
        guard [16, 24, 32].contains(keyDataLength) else {
            fatalError("Not a valid key length: \(keyDataLength)")
        }
        self._keyDataLength = keyDataLength
        self.protected = protected
        self.other = other
    }
    
    ///  Encodes the supplementary public information.
    /// - Returns: A CBOR array representing the supplementary public information.
    func encode() throws -> [CBOR] {
        // Convert `protected` to a CBOR.Map by mapping its keys and values
        let protectedMap: OrderedDictionary<CBOR, CBOR> = OrderedDictionary(
            uniqueKeysWithValues: try protected.compactMap {
                if let key = $0.key as? Int, let value = $0.value as? Int {
                    return (CBOR.unsignedInt(UInt64(key)), CBOR.unsignedInt(UInt64(value)))
                } else if let key = $0.key as? String, let value = $0.value as? String {
                    return (CBOR.utf8String(key), CBOR.utf8String(value))
                } else if let key = $0.key as? Int, let value = $0.value as? String {
                    return (CBOR.unsignedInt(UInt64(key)), CBOR.utf8String(value))
                } else if let key = $0.key as? String, let value = $0.value as? Int {
                    return (CBOR.utf8String(key), CBOR.unsignedInt(UInt64(value)))
                } else {
                    throw CoseError.valueError("Invalid key-value pair in `protected`: key=\($0.key), value=\($0.value)")
                }
            }
        )
        
        var info: [CBOR] = [
            CBOR.unsignedInt(UInt64(keyDataLength * 8)),
            CBOR.map(protectedMap)
        ]
        
        if !other.isEmpty {
            info.append(try! CBORSerialization.cbor(from: other))
        }
        return info
    }
    
    /// Custom CBOR encoder for special header values.
    /// - Parameter value: The value to encode.
    /// - Returns: A CBOR-encoded representation of the value.
    private func customCBORValueEncoder(_ value: CoseAttribute) -> CBOR {
        return CBOR.unsignedInt(UInt64(value.identifier))
    }
}

public struct CoseKDFContext {
    var algorithm: EncAlgorithm
    var suppPubInfo: SuppPubInfo
    var partyUInfo: PartyInfo = PartyInfo()
    var partyVInfo: PartyInfo = PartyInfo()
    var suppPrivInfo: Data = Data()

    func encode() throws -> Data {
        var context: [CBOR] = [
            CBOR.unsignedInt(UInt64(algorithm.identifier)),
            CBOR.array(partyUInfo.encode()),
            CBOR.array(partyVInfo.encode()),
            CBOR.array(try suppPubInfo.encode())
        ]

        if !suppPrivInfo.isEmpty {
            context.append(try! CBORSerialization.cbor(from: suppPrivInfo))
        }

        return try CBORSerialization.data(from: .array(context))
    }
}
