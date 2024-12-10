import Foundation
import UncommonCrypto
import CryptoKit

public enum Curve {
    case nist256p(P256)
    case nist384p(P384)
//    case edwardsPrivateKey(EdwardsPrivateKey)
    case none
}


public enum KeyType {
    case ktyEC2(KtyEC2)
    case ktyOKP(KtyOKP)
    case none
}


public enum CoseCurveIdentifier: Int, Codable, Equatable {
    case reserved = 0
    case p256 = 1
    case p384 = 2
    case p521 = 3
    case x25519 = 4
    case x448 = 5
    case ed25519 = 6
    case ed448 = 7
    case secp256k1 = 8
}

// Base Protocol for COSE Curves
public class CoseCurve: CoseAttribute {
    public var keyType: KeyType?
    public var size: Int
    
    public init(
        identifier: CoseCurveIdentifier,
        fullname: String,
        size: Int,
        keyType: KeyType? = nil,
    ) {
        self.keyType = keyType
        self.size = size
        super.init(identifier: identifier.rawValue, fullname: fullname)
    }
}


// MARK: - Concrete Curve Implementations

public class ReservedCurve: CoseCurve {
    public init() {
        super.init(
            identifier: .reserved,
            fullname: "RESERVED",
            size: 0
        )
    }
}

public class P256Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .p256,
            fullname: "P_256",
            size: 32,
            keyType: .ktyEC2(P256())
        )
    }
}

public class P384Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .p384,
            fullname: "P_384",
            size: 48,
            keyType: .ktyEC2(P384())
        )
    }
}

public class P521Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .p521,
            fullname: "P_521",
            size: 66,
            keyType: .ktyEC2(P521())
        )
    }
}

public class X25519Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .x25519,
            fullname: "X25519",
            size: 32,
            keyType: .ktyOKP(KtyOKP())
        )
    }
}

public class X448Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .x448,
            fullname: "X448",
            size: 57,
            keyType: .ktyOKP(KtyOKP())
        )
    }
}

public class Ed25519Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .ed25519,
            fullname: "ED25519",
            size: 32,
            keyType: .ktyOKP(KtyOKP())
        )
    }
}

public class Ed448Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .ed448,
            fullname: "ED448",
            size: 57,
            keyType: .ktyOKP(KtyOKP())
        )
    }
}

public class SECP256K1Curve: CoseCurve {
    public init() {
        super.init(
            identifier: .secp256k1,
            fullname: "SECP256K1",
            size: 32,
            keyType: .ktyEC2(P256())
        )
    }
}
