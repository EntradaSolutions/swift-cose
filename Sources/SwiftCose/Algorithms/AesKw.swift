import Foundation
import CryptoKit

public class AesKwAlgorithm: EncAlgorithm {
    public func keyWrap(kek: CoseSymmetricKey, data: Data) throws -> Data {
        guard keyLength == kek.k.count else {
            throw CoseError.invalidKey("Key has the wrong length")
        }
        
        // Use the AES Key Wrap algorithm (RFC 3394) for key wrapping
        let wrappedKey = try AES.KeyWrap.wrap(
            SymmetricKey(data: data),
            using: SymmetricKey(data: kek.k)
        )
        return wrappedKey
    }

    public func keyUnwrap(kek: CoseSymmetricKey, data: Data) throws -> Data {
        guard keyLength == kek.k.count else {
            throw CoseError.invalidKey("Key has the wrong length")
        }
        
        // Use the AES Key Unwrap algorithm (RFC 3394) for key unwrapping
        let unwrappedKey = try AES.KeyWrap.unwrap(data.toBytes, using: SymmetricKey(data: kek.k))
        return unwrappedKey.withUnsafeBytes { Data($0) }
    }
}

/// AES Key Wrap with a 128-bit key
public class A128KW: AesKwAlgorithm {
    public init() {
        super.init(identifier: .aesKW_128, fullname: "A128KW", keyLength: 16)
    }
}

/// AES Key Wrap with a 192-bit key
public class A192KW: AesKwAlgorithm {
    public init() {
        super.init(identifier: .aesKW_192, fullname: "A192KW", keyLength: 24)
    }
}

// AES Key Wrap with a 256-bit key
public class A256KW: AesKwAlgorithm {
    public init() {
        super.init(identifier: .aesKW_256, fullname: "A256KW", keyLength: 32)
    }
}

