import Foundation

/// Abstract base class for SignCommon
public class SignCommon: CoseMessage {

    // MARK: - Abstract Properties
    public var signature: Data? {
        fatalError("Subclasses must implement the 'signature' property")
    }

    // MARK: - Abstract Methods
    /// Creates the signature structure. Must be implemented by subclasses.
    /// - Parameter detachedPayload: The optional detached payload.
    /// - Returns: The byte representation of the signature structure.
    public func createSignatureStructure(detachedPayload: Data? = nil) throws -> Data {
        fatalError("Subclasses must implement the 'createSigStructure' method")
    }

    // MARK: - Methods
    /// Verifies the key type and ensures the correct operations are supported.
    /// - Parameters:
    ///   - alg: The algorithm type.
    ///   - ops: The key operations.
    public func keyVerification(alg: CoseAlgorithm, ops: KeyOps) throws {
        guard let key = self.key else {
            throw CoseError.valueError("Key cannot be nil")
        }

        switch key {
            case let ec2Key as EC2Key:
                try ec2Key
                    .verify(keyType: EC2Key.self, algorithm: alg, keyOps: [ops])
            case let okpKey as OKPKey:
                try okpKey
                    .verify(keyType: OKPKey.self, algorithm: alg, keyOps: [ops])
            case let rsaKey as RSAKey:
                try rsaKey
                    .verify(keyType: RSAKey.self, algorithm: alg, keyOps: [ops])
            default:
                throw CoseError.invalidKey("Unsupported key type")
        }
    }

    /// Verifies the signature of a received COSE message.
    /// - Parameters:
    ///   - detachedPayload: The optional detached payload.
    /// - Returns: `true` if the signature is valid, otherwise `false`.
    public func verifySignature(detachedPayload: Data? = nil) throws -> Bool {
        guard let alg = try getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidHeader("Algorithm attribute is missing or invalid")
        }

        try keyVerification(alg: alg, ops: VerifyOp())
        let data = try createSignatureStructure(
            detachedPayload: detachedPayload
        )
        
        if let alg = alg as? EcdsaAlgorithm {
            return try alg.verify(
                key: self.key as! EC2Key,
                data: data,
                signature: self.signature!
            )
        } else if let alg = alg as? EdDSAAlgorithm {
            return try alg.verify(
                key: self.key as! OKPKey,
                data: data,
                signature: self.signature!
            )
        } else if let alg = alg as? RsaAlgorithm {
            return try alg.verify(
                key: self.key as! RSAKey,
                data: data,
                signature: self.signature!
            )
        } else {
            throw CoseError.invalidAlgorithm("Unsupported algorithm")
        }
    }

    /// Computes the signature over a COSE message.
    /// - Parameters:
    ///   - detachedPayload: The optional detached payload.
    /// - Returns: The computed signature as `Data`.
    public func computeSignature(detachedPayload: Data? = nil) throws -> Data {
        guard let alg = try getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidHeader("Algorithm attribute is missing or invalid")
        }

        try keyVerification(alg: alg, ops: SignOp())
        
        if let alg = alg as? EcdsaAlgorithm {
            return try alg.sign(
                key: self.key as! EC2Key,
                data: createSignatureStructure(detachedPayload: detachedPayload)
            )
        } else if let alg = alg as? EdDSAAlgorithm {
            return try alg.sign(
                key: self.key as! OKPKey,
                data: createSignatureStructure(detachedPayload: detachedPayload)
            )
        } else if let alg = alg as? RsaAlgorithm {
            return try alg.sign(
                key: self.key as! RSAKey,
                data: createSignatureStructure(detachedPayload: detachedPayload)
            )
        } else {
            throw CoseError.invalidAlgorithm("Unsupported algorithm")
        }
    }
}
