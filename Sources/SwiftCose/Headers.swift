import Foundation

public struct Headers {
    public var protected: Dictionary<String, Any>
    public var unprotected: Dictionary<String, Any>
}

//private enum CodingKeys: String, CodingKey {
//    case identifier
//    case fullname
//    case registeredAttributes
//}

public enum CoseHeaderIdentifier: Int, Codable {
    case reserved = 0
    case algorithm = 1
    case critical = 2
    case contentType = 3
    case kid = 4
    case iv = 5
    case partialIV = 6
    case counterSignature = 7
    case counterSignature0 = 9
    case kidContext = 10
    case x5bag = 32
    case x5chain = 33
    case x5t = 34
    case x5u = 35
    case ephemeralKey = -1
    case staticKey = -2
    case staticKeyID = -3
    case salt = -20
    case partyUID = -21
    case partyUNonce = -22
    case partyUOther = -23
    case partyVID = -24
    case partyVNonce = -25
    case partyVOther = -26
    case suppPubOther = -998
    case suppPrivOther = -999
}

public class CoseHeaderAttribute: CoseAttribute {
    public init(
        identifier: CoseHeaderIdentifier,
        fullname: String,
        valueParser: ((Any) throws -> Any)? = nil
    ) {
        super.init(identifier: identifier.rawValue, fullname: fullname, valueParser: valueParser)
    }
    
    public static func getInstance(for identifier: CoseHeaderIdentifier) -> CoseHeaderAttribute {
        switch identifier {
            case .reserved: return Reserved()
            case .algorithm: return Algorithm()
            case .critical: return Critical()
            case .contentType: return ContentType()
            case .kid: return KID()
            case .iv: return IV()
            case .partialIV: return PartialIV()
            case .counterSignature: return CounterSignature()
            case .counterSignature0: return CounterSignature0()
            case .kidContext: return KIDContext()
            case .x5bag: return X5bag()
            case .x5chain: return X5chain()
            case .x5t: return X5t()
            case .x5u: return X5u()
            case .ephemeralKey: return EphemeralKey()
            case .staticKey: return StaticKey()
            case .staticKeyID: return StaticKeyID()
            case .salt: return Salt()
            case .partyUID: return PartyUID()
            case .partyUNonce: return PartyUNonce()
            case .partyUOther: return PartyUOther()
            case .partyVID: return PartyVID()
            case .partyVNonce: return PartyVNonce()
            case .partyVOther: return PartyVOther()
            case .suppPubOther: return SuppPubOther()
            case .suppPrivOther: return SuppPrivOther()
        }
    }
}

final class Reserved: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .reserved, fullname: "RESERVED")
    }
}

final class Algorithm: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .algorithm, fullname: "ALG")
    }
}

final class Critical: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .critical, fullname: "CRITICAL", valueParser: critIsArray)
    }
}

final class ContentType: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .contentType, fullname: "CONTENT_TYPE", valueParser: contentTypeIsUIntOrTstr)
    }
}

final class KID: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .kid, fullname: "KID", valueParser: isBstr)
    }
}

final class IV: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .iv, fullname: "IV", valueParser: isBstr)
    }
}

final class PartialIV: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partialIV, fullname: "PARTIAL_IV", valueParser: isBstr)
    }
}

final class CounterSignature: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .counterSignature, fullname: "COUNTER_SIGN")
    }
}

final class CounterSignature0: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .counterSignature0, fullname: "COUNTER_SIGN0", valueParser: isBstr)
    }
}

final class KIDContext: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .kidContext, fullname: "KID_CONTEXT", valueParser: isBstr)
    }
}

final class X5bag: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .x5bag, fullname: "X5_BAG")
    }
}

final class X5chain: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .x5chain, fullname: "X5_CHAIN")
    }
}

final class X5t: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .x5t, fullname: "X5_T")
    }
}

final class X5u: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .x5u, fullname: "X5_U")
    }
}

final class EphemeralKey: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .ephemeralKey, fullname: "EPHEMERAL_KEY")
    }
}

final class StaticKey: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .staticKey, fullname: "STATIC_KEY")
    }
}

final class StaticKeyID: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .staticKeyID, fullname: "STATIC_KEY_ID")
    }
}

final class Salt: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .salt, fullname: "SALT")
    }
}

final class PartyUID: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partyUID, fullname: "PARTY_U_ID")
    }
}

final class PartyUNonce: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partyUNonce, fullname: "PARTY_U_NONCE")
    }
}

final class PartyUOther: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partyUOther, fullname: "PARTY_U_OTHER")
    }
}

final class PartyVID: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partyVID, fullname: "PARTY_V_ID")
    }
}

final class PartyVNonce: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partyVNonce, fullname: "PARTY_V_NONCE")
    }
}

final class PartyVOther: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .partyVOther, fullname: "PARTY_V_OTHER")
    }
}

final class SuppPubOther: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .suppPubOther, fullname: "SUPP_PUB_OTHER")
    }
}

final class SuppPrivOther: CoseHeaderAttribute {
    public init() {
        super.init(identifier: .suppPrivOther, fullname: "SUPP_PRIV_OTHER")
    }
}

func isBstr(_ value: Any) throws -> Any {
    guard let _ = value as? Data else {
        throw CoseError.invalidKIDValue("Key ID must be a byte string")
    }
    return value
}

func critIsArray(_ value: Any) throws -> Any {
    guard let array = value as? [Any], !array.isEmpty,
          array.allSatisfy({ $0 is Int || $0 is String }) else {
        throw CoseError.invalidCriticalValue("Critical values must be a non-empty array of integers or strings")
    }
    return value
}

func contentTypeIsUIntOrTstr(_ value: Any) throws -> Any {
    if let intVal = value as? Int, intVal >= 0 {
        return value
    } else if value is String {
        return value
    }
    throw CoseError.invalidContentType("Content type must be a non-negative integer or text string")
}
