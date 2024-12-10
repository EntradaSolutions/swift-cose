import Foundation
import _CryptoExtras

public enum Padding {
    case pkcs1_oaep
    case pkcs1_oaep_sha256
    case pkcs1v1_5
    case pss
    case pssZero
}

/// RSA signing and (key-wrap) encryption.
public class Rsa: CoseAlgorithm {
    public var hashFunction: CoseHashFunction
    
    public var padding: Padding {
        fatalError("Must be implemented by subclasses")
    }
    
    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        hashFunction: CoseHashFunction
    ) {
        self.hashFunction = hashFunction
        super.init(identifier: identifier, fullname: fullname)
    }
    
    public func sign(key: RSAKey, data: Data) throws -> _RSA.Signing.RSASignature {
        // Construct the private key
        _ = try _RSA.Signing.PublicKey(n: key.n, e: key.e)
        let privateKey =  try _RSA.Signing.PrivateKey(n: key.n, e: key.e, d: key.d, p: key.p, q: key.q)
        
        // Sign the data
        switch padding {
            case .pkcs1v1_5:
                return try privateKey.signature(for: data, padding: .insecurePKCS1v1_5)
            case .pss:
                return try privateKey.signature(for: data, padding: .PSS)
            default:
                throw CoseError.valueError("Unsupported padding")
        }
    }
        
    public func verify(key: RSAKey, data: Data, signature: _RSA.Signing.RSASignature) -> Bool {
        do {
            // Construct the public key
            let rsaPublicKey = try _RSA.Signing.PublicKey(n: key.n, e: key.e)
            
            // Verify the signature
            switch padding {
                case .pkcs1v1_5:
                    return rsaPublicKey.isValidSignature(signature, for: data, padding: .insecurePKCS1v1_5)
                case .pss:
                    return rsaPublicKey.isValidSignature(signature, for: data, padding: .PSS)
                default:
                    throw CoseError.valueError("Unsupported padding")
            }
            
        } catch {
            return false
        }
    }
}

/// RSA with PSS padding
public class RsaPss: Rsa {
    override public var padding: Padding {
        return .pss
    }
}

/// RSA with OAEP padding
public class RsaOaep: Rsa {
    override public var padding: Padding {
        return .pkcs1_oaep_sha256
    }

    func keyWrap(key: RSAKey, data: Data) throws -> Data {
        let rsaPublicKey = try _RSA.Encryption.PublicKey(n: key.n, e: key.e)
        
        switch padding {
            case .pkcs1_oaep:
                return try rsaPublicKey
                    .encrypt(data, padding: _RSA.Encryption.Padding.PKCS1_OAEP)
            case .pkcs1_oaep_sha256:
                return try rsaPublicKey
                    .encrypt(data, padding: _RSA.Encryption.Padding.PKCS1_OAEP_SHA256)
            default:
                throw CoseError.valueError("Unsupported padding")
        }
    }

    func keyUnwrap(key: RSAKey, data: Data) throws -> Data {
        // Construct the private key
        _ = try _RSA.Encryption.PublicKey(n: key.n, e: key.e)
        let privateKey =  try _RSA.Encryption.PrivateKey(n: key.n, e: key.e, d: key.d, p: key.p, q: key.q)
        
        switch padding {
            case .pkcs1_oaep:
                return try privateKey.decrypt(data, padding: _RSA.Encryption.Padding.PKCS1_OAEP)
            case .pkcs1_oaep_sha256:
                return try privateKey.decrypt(data, padding: _RSA.Encryption.Padding.PKCS1_OAEP_SHA256)
            default:
                throw CoseError.valueError("Unsupported padding")
        }
        
        
    }
}

/// RSA with PKCS#1 padding
public class RsaPkcs1: Rsa {
    override public var padding: Padding {
        return .pkcs1v1_5
    }
}

/// Base class for RSA OAEP algorithms
public class RsaesOaep: Rsa {
    public override var padding: Padding {
        return .pkcs1_oaep
    }
}

/// RSAES-OAEP-SHA512
public class RsaesOaepSha512: RsaesOaep {
    public init() {
        super.init(
            identifier: .rsa_ES_OAEP_SHA512,
            fullname: "RSAES_OAEP_SHA_512",
            hashFunction: .sha512
        )
    }
}

/// RSAES-OAEP-SHA256
public class RsaesOaepSha256: RsaesOaep {
    public init() {
        super.init(
            identifier: .rsa_ES_OAEP_SHA256,
            fullname: "RSAES_OAEP_SHA_256",
            hashFunction: .sha256
        )
    }
}

/// RSAES-OAEP-SHA1
public class RsaesOaepSha1: RsaesOaep {
    public init() {
        super.init(
            identifier: .rsa_ES_OAEP_SHA1,
            fullname: "RSAES_OAEP_SHA_1",
            hashFunction: .sha1
        )
    }
}

/// PS512
public class Ps512: RsaPss {
    public init() {
        super.init(
            identifier: .ps512,
            fullname: "PS512",
            hashFunction: .sha512
        )
    }
}

/// PS384
public class Ps384: RsaPss {
    public init() {
        super.init(
            identifier: .ps384,
            fullname: "PS384",
            hashFunction: .sha384
        )
    }
}

/// PS256
public class Ps256: RsaPss {
    public init() {
        super.init(
            identifier: .ps256,
            fullname: "PS256",
            hashFunction: .sha256
        )
    }
}

/// RSASSA-PKCS1-v1_5 using SHA-1
public class RsaPkcs1Sha1: RsaPkcs1 {
    public init() {
        super.init(
            identifier: .rsa_PKCS1_SHA1,
            fullname: "RS1",
            hashFunction: .sha1
        )
    }
}

/// RSASSA-PKCS1-v1_5 using SHA-512
public class RsaPkcs1Sha512: RsaPkcs1 {
    public init() {
        super.init(
            identifier: .rsa_PKCS1_SHA512,
            fullname: "RS512",
            hashFunction: .sha512
        )
    }
}

/// RSASSA-PKCS1-v1_5 using SHA-384
public class RsaPkcs1Sha384: RsaPkcs1 {
    public init() {
        super.init(
            identifier: .rsa_PKCS1_SHA384,
            fullname: "RS384",
            hashFunction: .sha384
        )
    }
}

/// RSASSA-PKCS1-v1_5 using SHA-256
public class RsaPkcs1Sha256: RsaPkcs1 {
    public init() {
        super.init(
            identifier: .rsa_PKCS1_SHA256,
            fullname: "RS256",
            hashFunction: .sha256
        )
    }
}
