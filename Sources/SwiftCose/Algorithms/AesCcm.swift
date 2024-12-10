import Foundation
import CryptoSwift


public class AesCcmAlgorithm: EncAlgorithm {
    public var tagLength: Int
    
    public init(
        identifier: CoseAlgorithmIdentifier,
        fullname: String,
        keyLength: Int,
        tagLength: Int
    ) {
        self.tagLength = tagLength
        super.init(identifier: identifier, fullname: fullname, keyLength: keyLength)
    }

    public func encrypt(key: CoseSymmetricKey, nonce: Data, data: Data, aad: Data?) throws -> Data {
        let aes = try! AES(
            key: key.k.toBytes,
            blockMode:
                CCM(
                    iv: nonce.toBytes,
                    tagLength: tagLength,
                    messageLength: data.count - 4,
                    additionalAuthenticatedData: aad?.toBytes
                ),
            padding: .noPadding
        )
        let encrypted = try! aes.encrypt(data.toBytes)
        return encrypted.toData
    }

    public func decrypt(key: CoseSymmetricKey, nonce: Data, ciphertext: Data, aad: Data?) throws -> Data {
        let aes = try! AES(
            key: key.k.toBytes,
            blockMode:
                CCM(
                    iv: nonce.toBytes,
                    tagLength: tagLength,
                    messageLength: ciphertext.count - 4,
                    additionalAuthenticatedData: aad?.toBytes
                ),
            padding: .noPadding
        )
        let decrypted = try! aes.decrypt(ciphertext.toBytes)
        return decrypted.toData
    }
}

/// AES-CCM with a tag length of 8 bytes and a key length of 16 bytes
public class AESCCM1664128: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_16_64_128,
            fullname: "AES_CCM_16_64_128",
            keyLength: 16,
            tagLength: 8
        )
    }
}

/// AES-CCM with a tag length of 8 bytes and a key length of 32 bytes
public class AESCCM1664256: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_16_64_256,
            fullname: "AES_CCM_16_64_256",
            keyLength: 32,
            tagLength: 8
        )
    }
}

/// AES-CCM with a tag length of 8 bytes and a key length of 16 bytes
public class AESCCM6464128: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_64_64_128,
            fullname: "AES_CCM_64_64_128",
            keyLength: 16,
            tagLength: 8
        )
    }
}

/// AES-CCM with a tag length of 8 bytes and a key length of 32 bytes
public class AESCCM6464256: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_64_64_256,
            fullname: "AES_CCM_64_64_256",
            keyLength: 32,
            tagLength: 8
        )
    }
}

/// AES-CCM with a tag length of 16 bytes and a key length of 16 bytes
public class AESCCM16128128: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_16_128_128,
            fullname: "AES_CCM_16_128_128",
            keyLength: 16,
            tagLength: 16
        )
    }
}

/// AES-CCM with a tag length of 16 bytes and a key length of 32 bytes
public class AESCCM16128256: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_16_128_256,
            fullname: "AES_CCM_16_128_256",
            keyLength: 32,
            tagLength: 16
        )
    }
}

/// AES-CCM with a tag length of 16 bytes and a key length of 16 bytes
public class AESCCM64128128: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_64_128_128,
            fullname: "AES_CCM_64_128_128",
            keyLength: 16,
            tagLength: 16
        )
    }
}

/// AES-CCM with a tag length of 16 bytes and a key length of 32 bytes
public class AESCCM64128256: AesCcmAlgorithm {
    public init() {
        super.init(
            identifier: .aesCCM_64_128_256,
            fullname: "AES_CCM_64_128_256",
            keyLength: 32,
            tagLength: 16
        )
    }
}
