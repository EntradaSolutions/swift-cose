import Foundation
import CryptoKit
@_implementationOnly import OpenSSL

public enum CoseAlgorithmIdentifier: Int, Codable, Equatable {
    case aesCCM_16_64_128 = 10
    case aesCCM_16_64_256 = 11
    case aesCCM_64_64_128 = 12
    case aesCCM_64_64_256 = 13
    case aesCCM_16_128_128 = 30
    case aesCCM_16_128_256 = 31
    case aesCCM_64_128_128 = 32
    case aesCCM_64_128_256 = 33
    case aesGCM_128 = 1
    case aesGCM_192 = 2
    case aesGCM_256 = 3
    case aesKW_128 = -3
    case aesKW_192 = -4
    case aesKW_256 = -5
    case aesMAC_128_64 = 14
    case aesMAC_256_64 = 15
    case aesMAC_128_128 = 25
    case aesMAC_256_128 = 26
    case direct = -6
    case directHKDFAES128 = -12
    case directHKDFAES256 = -13
    case directHKDFSHA256 = -10
    case direcHKDFSHA512 = -11
    case edDSA = -8
    case es256 = -7
    case es384 = -35
    case es512 = -36
    case ecdhES_A128KW = -29
    case ecdhES_A192KW = -30
    case ecdhES_A256KW = -31
    case ecdhES_HKDF_256 = -25
    case ecdhES_HKDF_512 = -26
    case ecdhSS_A128KW = -32
    case ecdhSS_A192KW = -33
    case ecdhSS_A256KW = -34
    case ecdhSS_HKDF_256 = -27
    case ecdhSS_HKDF_512 = -28
    case hmacSHA256 = 5
    case hmacSHA256_64 = 4
    case hmacSHA384 = 6
    case hmacSHA512 = 7
    case ps256 = -37
    case ps384 = -38
    case ps512 = -39
    case rsa_ES_OAEP_SHA1 = -40
    case rsa_ES_OAEP_SHA256 = -41
    case rsa_ES_OAEP_SHA512 = -42
    case rsa_PKCS1_SHA1 = -65535
    case rsa_PKCS1_SHA256 = -257
    case rsa_PKCS1_SHA384 = -258
    case rsa_PKCS1_SHA512 = -259
    case sha1 = -14
    case sha256 = -16
    case sha256_64 = -15
    case sha384 = -43
    case sha512 = -44
    case sha512_256 = -17
    case shake128 = -18
    case shake256 = -45
}

public class CoseAlgorithm: CoseAttribute {
    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        valueParser: ((Any) throws -> Any)? = nil
    ) {
        super.init(identifier: identifier.rawValue, fullname: fullname, valueParser: valueParser)
    }

    public static func getInstance(for identifier: CoseAlgorithmIdentifier) throws -> CoseAlgorithm {
        switch identifier {
            case .direct:
                return Direct()
            case .directHKDFAES128:
                return DirectHKDFAES128()
            case .directHKDFAES256:
                return DirectHKDFAES256()
            case .directHKDFSHA256:
                return DirectHKDFSHA256()
            case .direcHKDFSHA512:
                return DirecHKDFSHA512()
            case .edDSA:
                return EdDSA()
            case .sha1:
                return Sha1()
            case .sha256:
                return Sha256()
            case .sha256_64:
                return Sha256Trunc64()
            case .sha384:
                return Sha384()
            case .sha512:
                return Sha512()
            case .sha512_256:
                return Sha512Trunc64()
            case .shake128:
                return Shake128()
            case .shake256:
                return Shake256()
            case .aesCCM_16_64_128:
                return AESCCM1664128()
            case .aesCCM_16_64_256:
                return AESCCM1664256()
            case .aesCCM_64_64_128:
                return AESCCM6464128()
            case .aesCCM_64_64_256:
                return AESCCM6464256()
            case .aesCCM_16_128_128:
                return AESCCM16128128()
            case .aesCCM_16_128_256:
                return AESCCM16128256()
            case .aesCCM_64_128_128:
                return AESCCM64128128()
            case .aesCCM_64_128_256:
                return AESCCM64128256()
            case .aesGCM_128:
                return A128GCM()
            case .aesGCM_192:
                return A192GCM()
            case .aesGCM_256:
                return A256GCM()
            case .aesKW_128:
                return A128KW()
            case .aesKW_192:
                return A192KW()
            case .aesKW_256:
                return A256KW()
            case .aesMAC_128_64:
                return AESMAC12864()
            case .aesMAC_256_64:
                return AESMAC25664()
            case .aesMAC_128_128:
                return AESMAC128128()
            case .aesMAC_256_128:
                return AESMAC256128()
            case .es256:
                return Es256()
            case .es384:
                return Es384()
            case .es512:
                return Es512()
            case .ecdhES_A128KW:
                return EcdhEsA128KW()
            case .ecdhES_A192KW:
                return EcdhEsA192KW()
            case .ecdhES_A256KW:
                return EcdhEsA256KW()
            case .ecdhES_HKDF_256:
                return EcdhEsHKDF256()
            case .ecdhES_HKDF_512:
                return EcdhEsHKDF512()
            case .ecdhSS_A128KW:
                return EcdhSsA128KW()
            case .ecdhSS_A192KW:
                return EcdhSsA192KW()
            case .ecdhSS_A256KW:
                return EcdhSsA256KW()
            case .ecdhSS_HKDF_256:
                return EcdhSsHKDF256()
            case .ecdhSS_HKDF_512:
                return EcdhSsHKDF512()
            case .hmacSHA256:
                return Hmac256()
            case .hmacSHA256_64:
                return Hmac25664()
            case .hmacSHA384:
                return Hmac384()
            case .hmacSHA512:
                return Hmac512()
            case .ps256:
                return Ps256()
            case .ps384:
                return Ps384()
            case .ps512:
                return Ps512()
            case .rsa_ES_OAEP_SHA1:
                return RsaesOaepSha1()
            case .rsa_ES_OAEP_SHA256:
                return RsaesOaepSha256()
            case .rsa_ES_OAEP_SHA512:
                return RsaesOaepSha512()
            case .rsa_PKCS1_SHA1:
                return RsaPkcs1Sha1()
            case .rsa_PKCS1_SHA256:
                return RsaPkcs1Sha256()
            case .rsa_PKCS1_SHA384:
                return RsaPkcs1Sha384()
            case .rsa_PKCS1_SHA512:
                return RsaPkcs1Sha512()
        }
    }

}

public class EncAlgorithm: CoseAlgorithm {
    public var keyLength: Int?
    
    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        keyLength: Int? = nil
    ) {
        self.keyLength = keyLength
        super.init(identifier: identifier, fullname: fullname)
    }
}

/// Direct use of CEK
public class Direct: CoseAlgorithm {
    public init() {
        super.init(identifier: .direct, fullname: "DIRECT")
    }
}

/// Shared secret w/ AES-MAC 128-bit key
public class DirectHKDFAES128: CoseAlgorithm {
    public init() {
        super.init(identifier: .directHKDFAES128, fullname: "DIRECT_HKDF_AES_128")
    }
}

/// Shared secret w/ AES-MAC 256-bit key
public class DirectHKDFAES256: CoseAlgorithm {
    public init() {
        super.init(identifier: .directHKDFAES256, fullname: "DIRECT_HKDF_AES_256")
    }
}

/// Shared secret w/ HKDF and SHA-256
public class DirectHKDFSHA256: CoseAlgorithm {
    public init() {
        super.init(identifier: .directHKDFSHA256, fullname: "DIRECT_HKDF_SHA_256")
    }
}

/// Shared secret w/ HKDF and SHA-512
public class DirecHKDFSHA512: CoseAlgorithm {
    public init() {
        super.init(identifier: .direcHKDFSHA512, fullname: "DIRECT_HKDF_SHA_512")
    }
}


/// EdDSA
public class EdDSA: CoseAlgorithm {
    public init() {
        super.init(identifier: .edDSA, fullname: "EDDSA")
    }
    
    public class func sign(key: OKPKey, data: Data) throws -> Data {
        switch key.curve.fullname {
        case "ED25519":
                guard let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: key.d!) else {
                throw CoseError.invalidKey("Invalid private key")
            }
            return try privateKey.signature(for: data)
            
        case "ED448":
                guard let privateKey = try? Curve448.KeyAgreement.PrivateKey(rawRepresentation: key.d!) else {
                throw CoseError.invalidKey("Invalid private key")
            }
            return privateKey.signature(for: data)
            
        default:
            throw CoseError.illegalCurve("Unsupported curve")
        }
    }

    public class func verify(key: OKPKey, data: Data, signature: Data) -> Bool {
        switch key.curve.fullname {
        case "ED25519":
            guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: key.x) else {
                return false
            }
            return publicKey.isValidSignature(signature, for: data)
            
        case "ED448":
            // Assuming Ed448 functionality is available in your crypto library
                guard let publicKey = try? Curve448.KeyAgreement.PublicKey(rawRepresentation: key.x) else {
                return false
            }
            return publicKey.isValidSignature(signature, for: data)
            
        default:
            return false
        }
    }
}
