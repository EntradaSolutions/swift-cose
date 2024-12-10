import Foundation
import PotentCBOR

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
    var protected: Dictionary<String, CBOR> = [:]
    var other: Data = Data()

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

    init(keyDataLength: Int, protected: Dictionary<String, CBOR> = [:], other: Data = Data()) {
        guard [16, 24, 32].contains(keyDataLength) else {
            fatalError("Not a valid key length: \(keyDataLength)")
        }
        self._keyDataLength = keyDataLength
        self.protected = protected
        self.other = other
    }

    func encode() -> [CBOR] {
        // Convert `protected` to a CBOR.Map by mapping its keys and values
        let protectedMap: CBOR.Map = protected.map { (CBOR.utf8String($0.key), $0.value) }
        
        var info: [CBOR] = [
            CBOR.unsignedInt(UInt64(keyDataLength * 8)),
            CBOR.map(protectedMap)
        ]
        if !other.isEmpty {
            info.append(try! CBORSerialization.cbor(from: other))
        }
        return info
    }
}

public struct CoseKDFContext {
    var algorithm: EncAlgorithm
    var suppPubInfo: SuppPubInfo
    var partyUInfo: PartyInfo = PartyInfo()
    var partyVInfo: PartyInfo = PartyInfo()
    var suppPrivInfo: Data = Data()

    func encode() -> Data {
        var context: [CBOR] = [
            CBOR.unsignedInt(UInt64(algorithm.identifier)),
            CBOR.array(partyUInfo.encode()),
            CBOR.array(partyVInfo.encode()),
            CBOR.array(suppPubInfo.encode())
        ]

        if !suppPrivInfo.isEmpty {
            context.append(CBOR.data(suppPrivInfo))
        }

        return CBOR.encode(context)
    }
}
