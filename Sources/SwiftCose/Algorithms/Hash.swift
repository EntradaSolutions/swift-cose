import Foundation
import UncommonCrypto
import Digest

public class HashAlgorithm: CoseAlgorithm {
    public var hashAlgorithm: CoseAlgorithmIdentifier
    public var truncSize: Int?
    
    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        truncSize: Int? = nil
    ) {
        self.hashAlgorithm = identifier
        self.truncSize = truncSize
        super.init(identifier: identifier, fullname: fullname)
    }

    public func computeHash(data: Data) throws -> Data {
        var hash: [UInt8]
        switch hashAlgorithm {
            case .sha1:
                hash = SHA1.hash(data: data)
            case .sha256, .sha256_64:
                hash = SHA2.hash(type: .sha256, data: data)
            case .sha384:
                hash = SHA3.hash(type: .sha384, data: data)
            case .sha512, .sha512_256:
                hash = SHA3.hash(type: .sha512, data: data)
            case .shake128:
                let shake = SHAKE(.SHAKE128)
                shake.update(data.toBytes)
                hash = shake.digest(32)
            case .shake256:
                let shake = SHAKE(.SHAKE256)
                shake.update(data.toBytes)
                hash = shake.digest(64)
            default:
                throw CoseError.invalidAlgorithm("Unsupported hash algorithm")
        }
        
        var digest = Data(hash)

        if let truncSize = truncSize {
            digest = digest.prefix(truncSize)
        }

        return digest
    }
}

public class Sha1: HashAlgorithm {
    public init() {
        super.init(identifier: .sha1, fullname: "SHA-1")
    }
}

public class Sha256: HashAlgorithm {
    public init() {
        super.init(identifier: .sha256, fullname: "SHA-256")
    }
}

public class Sha256Trunc64: HashAlgorithm {
    public init() {
        super.init(identifier: .sha256_64, fullname: "SHA-256/64", truncSize: 8)
    }
}

public class Sha384: HashAlgorithm {
    public init() {
        super.init(identifier: .sha384, fullname: "SHA-384")
    }
}

public class Sha512: HashAlgorithm {
    public init() {
        super.init(identifier: .sha512, fullname: "SHA-512")
    }
}

public class Sha512Trunc64: HashAlgorithm {
    public init() {
        super.init(identifier: .sha512_256, fullname: "SHA-512/256", truncSize: 32)
    }
}

public class Shake128: HashAlgorithm {
    public init() {
        super.init(identifier: .shake128, fullname: "SHAKE-128")
    }
}


public class Shake256: HashAlgorithm {
    public init() {
        super.init(identifier: .shake256, fullname: "SHAKE-256")
    }
}
