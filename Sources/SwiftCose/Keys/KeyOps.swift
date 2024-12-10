import Foundation

public enum KeyOpsIdentifier: Int, Codable, Equatable {
    case sign = 1
    case verify = 2
    case encrypt = 3
    case decrypt = 4
    case wrap = 5
    case unwrap = 6
    case deriveKey = 7
    case deriveBits = 8
    case macCreate = 9
    case macVerify = 10
}
    
public class KeyOps: CoseAttribute {
    public init(
        identifier: KeyOpsIdentifier,
        fullname: String
    ) {
        super.init(identifier: identifier.rawValue, fullname: fullname)
    }
}


public class SignOp: KeyOps {
    public init() {
        super.init(
            identifier: .sign,
            fullname: "SIGN"
        )
    }
}

public class VerifyOp: KeyOps {
    public init() {
        super.init(
            identifier: .verify,
            fullname: "VERIFY"
        )
    }
}

public class EncryptOp: KeyOps {
    public init() {
        super.init(
            identifier: .encrypt,
            fullname: "ENCRYPT"
        )
    }
}

public class DecryptOp: KeyOps {
    public init() {
        super.init(
            identifier: .decrypt,
            fullname: "DECRYPT"
        )
    }
}

public class WrapOp: KeyOps {
    public init() {
        super.init(
            identifier: .wrap,
            fullname: "WRAP"
        )
    }
}

public class UnwrapOp: KeyOps {
    public init() {
        super.init(
            identifier: .unwrap,
            fullname: "UNWRAP"
        )
    }
}

public class DeriveKeyOp: KeyOps {
    public init() {
        super.init(
            identifier: .deriveKey,
            fullname: "DERIVE_KEY"
        )
    }
}

public class DeriveBitsOp: KeyOps {
    public init() {
        super.init(
            identifier: .deriveBits,
            fullname: "DERIVE_BITS"
        )
    }
}

public class MacCreateOp: KeyOps {
    public init() {
        super.init(
            identifier: .macCreate,
            fullname: "MAC_CREATE"
        )
    }
}

public class MacVerifyOp: KeyOps {
    public init() {
        super.init(
            identifier: .macVerify,
            fullname: "MAC_VERIFY"
        )
    }
}
