import Foundation

// MARK: - Common Key Parameters

/// Enumerates the common key parameters
public enum KeyParamIdentifier: Int, Codable, Equatable {
    case kty = 1
    case kid = 2
    case alg = 3
    case keyOps = 4
    case baseIV = 5
    
}


public class KeyParam: CoseAttribute {
    public init(
        identifier: KeyParamIdentifier,
        fullname: String
    ) {
        super.init(identifier: identifier.rawValue, fullname: fullname)
    }
}

// Subclasses for common key parameters
public class KpKty: KeyParam {
    public init() {
        super.init(
            identifier: .kty,
            fullname: "KTY"
        )
    }
}

public class KpKid: KeyParam {
    public init() {
        super.init(
            identifier: .kid,
            fullname: "KID"
        )
    }
}

public class KpAlg: KeyParam {
    public init() {
        super.init(
            identifier: .alg,
            fullname: "ALG"
        )
    }
}

public class KpKeyOps: KeyParam {
    public init() {
        super.init(
            identifier: .keyOps,
            fullname: "KEY_OPS"
        )
    }
}

public class KpBaseIV: KeyParam {
    public init() {
        super.init(
            identifier: .baseIV,
            fullname: "BASE_IV"
        )
    }
}

// MARK: - EC2 Key Parameters

/// Enumerates the EC2 key parameters
public enum EC2KeyParamIdentifier: Int, Codable, Equatable {
    case curve = -1
    case x = -2
    case y = -3
    case d = -4
}
    
// Base class for EC2 key parameters
public class EC2KeyParam: CoseAttribute {
    public init(
        identifier: EC2KeyParamIdentifier,
        fullname: String
    ) {
        super.init(identifier: identifier.rawValue, fullname: fullname)
    }
}

public class EC2KpCurve: EC2KeyParam {
    public init() {
        super.init(
            identifier: .curve,
            fullname: "CURVE"
        )
    }
}

public class EC2KpX: EC2KeyParam {
    public init() {
        super.init(
            identifier: .x,
            fullname: "X"
        )
    }
}

public class EC2KpY: EC2KeyParam {
    public init() {
        super.init(
            identifier: .y,
            fullname: "Y"
        )
    }
}

public class EC2KpD: EC2KeyParam {
    public init() {
        super.init(
            identifier: .d,
            fullname: "D"
        )
    }
}

// MARK: - OKP Key Parameters

/// Enumerates the EC2 key parameters
public enum OKPKeyParamIdentifier: Int, Codable, Equatable {
    case curve = -1
    case x = -2
    case d = -4
}

// Base class for OKP key parameters
public class OKPKeyParam: CoseAttribute {
    public init(
        identifier: OKPKeyParamIdentifier,
        fullname: String
    ) {
        super.init(identifier: identifier.rawValue, fullname: fullname)
    }
}

// Subclasses for OKP key parameters
public class OKPKpCurve: OKPKeyParam {
    public init() {
        super.init(
            identifier: .curve,
            fullname: "CURVE"
        )
    }
}

public class OKPKpX: OKPKeyParam {
    public init() {
        super.init(
            identifier: .x,
            fullname: "X"
        )
    }
}

public class OKPKpD: OKPKeyParam {
    public init() {
        super.init(
            identifier: .d,
            fullname: "D"
        )
    }
}

// MARK: - RSA Key Parameters

/// Enumerates the EC2 key parameters
public enum RSAKeyParamIdentifier: Int, Codable, Equatable {
    case n = -1
    case e = -2
    case d = -3
    case p = -4
    case q = -5
    case dp = -6
    case dq = -7
    case qInv = -8
    case other = -9
    case r_i = -10
    case d_i = -11
    case t_i = -12
}

// Base class for RSA key parameters
public class RSAKeyParam: CoseAttribute {
    public init(
        identifier: RSAKeyParamIdentifier,
        fullname: String
    ) {
        super.init(identifier: identifier.rawValue, fullname: fullname)
    }
}

// Subclasses for RSA key parameters
public class RSAKpN: RSAKeyParam {
    public init() {
        super.init(
            identifier: .n,
            fullname: "N"
        )
    }
}

public class RSAKpE: RSAKeyParam {
    public init() {
        super.init(
            identifier: .e,
            fullname: "E"
        )
    }
}

public class RSAKpD: RSAKeyParam {
    public init() {
        super.init(
            identifier: .d,
            fullname: "D"
        )
    }
}

public class RSAKpP: RSAKeyParam {
    public init() {
        super.init(
            identifier: .p,
            fullname: "P"
        )
    }
}

public class RSAKpQ: RSAKeyParam {
    public init() {
        super.init(
            identifier: .q,
            fullname: "Q"
        )
    }
}

public class RSAKpDP: RSAKeyParam {
    public init() {
        super.init(
            identifier: .dp,
            fullname: "DP"
        )
    }
}

public class RSAKpDQ: RSAKeyParam {
    public init() {
        super.init(
            identifier: .dq,
            fullname: "DQ"
        )
    }
}

public class RSAKpQInv: RSAKeyParam {
    public init() {
        super.init(
            identifier: .qInv,
            fullname: "QINV"
        )
    }
}

public class RSAKpOther: RSAKeyParam {
    public init() {
        super.init(
            identifier: .other,
            fullname: "OTHER"
        )
    }
}

public class RSAKpRi: RSAKeyParam {
    public init() {
        super.init(
            identifier: .r_i,
            fullname: "R_I"
        )
    }
}

public class RSAKpDi: RSAKeyParam {
    public init() {
        super.init(
            identifier: .d_i,
            fullname: "D_I"
        )
    }
}

public class RSAKpTi: RSAKeyParam {
    public init() {
        super.init(
            identifier: .t_i,
            fullname: "T_I"
        )
    }
}


// MARK: - Symmetric Key Parameters

/// Enumerates the EC2 key parameters
public enum SymmetricKeyParamIdentifier: Int, Codable, Equatable {
    case k = -1
}

// Base class for Symmetric key parameters
public class SymmetricKeyParam: CoseAttribute {
    public init(
        identifier: SymmetricKeyParamIdentifier,
        fullname: String
    ) {
        super.init(identifier: identifier.rawValue, fullname: fullname)
    }
}

// Subclasses for Symmetric key parameters
public class SymKpK: SymmetricKeyParam {
    public init() {
        super.init(
            identifier: .k,
            fullname: "K"
        )
    }
}
