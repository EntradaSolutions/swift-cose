import Foundation

public enum KeyTypeIdentifier: Int, Codable, Equatable {
    case reserved = 0
    case okp = 1
    case ec2 = 2
    case rsa = 3
    case symmetric = 4
}

// Base class for key types
public class KTY: CoseAttribute {
    public init(
        identifier: KeyTypeIdentifier,
        fullname: String
    ) {
        super.init(identifier: identifier.rawValue, fullname: fullname)
    }
}

// Subclass for RESERVED key type
public class KtyReserved: KTY {
    public init() {
        super.init(
            identifier: .reserved,
            fullname: "RESERVED"
        )
    }
}

// Subclass for OKP key type
public class KtyOKP: KTY {
    public init() {
        super.init(
            identifier: .okp,
            fullname: "OKP"
        )
    }
}

// Subclass for EC2 key type
public class KtyEC2: KTY {
    public init() {
        super.init(
            identifier: .ec2,
            fullname: "EC2"
        )
    }
}

// Subclass for RSA key type
public class KtyRSA: KTY {
    public init() {
        super.init(
            identifier: .rsa,
            fullname: "RSA"
        )
    }
}

// Subclass for SYMMETRIC key type
public class KtySymmetric: KTY {
    public init() {
        super.init(
            identifier: .symmetric,
            fullname: "SYMMETRIC"
        )
    }
}
