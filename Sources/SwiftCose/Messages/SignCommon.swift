import Foundation

/// Abstract base class for SignCommon
open class SignCommon: CoseMessage {

    // MARK: - Abstract Properties
    open var signature: Data {
        fatalError("Subclasses must implement the 'signature' property")
    }

    // MARK: - Abstract Methods
    /// Creates the signature structure. Must be implemented by subclasses.
    /// - Parameter detachedPayload: The optional detached payload.
    /// - Returns: The byte representation of the signature structure.
    open func createSigStructure(detachedPayload: Data? = nil) -> Data {
        fatalError("Subclasses must implement the 'createSigStructure' method")
    }

    // MARK: - Key Verification
    /// Verifies the key type and ensures the correct operations are supported.
    /// - Parameters:
    ///   - alg: The algorithm type.
    ///   - ops: The key operations.
    func keyVerification(alg: CoseAlgorithm, ops: KeyOps) throws {
        guard let key = self.key else {
            throw CoseError.invalidKey("Key cannot be nil")
        }

        switch key {
        case let ec2Key as EC2Key:
            try ec2Key.verifyKeyType(expectedType: EC2Key.self, alg: alg, operations: [ops])
        case let okpKey as OKPKey:
            try okpKey.verifyKeyType(expectedType: OKPKey.self, alg: alg, operations: [ops])
        case let rsaKey as RSAKey:
            try rsaKey.verifyKeyType(expectedType: RSAKey.self, alg: alg, operations: [ops])
        default:
            throw CoseError.invalidKey("Unsupported key type")
        }
    }

    // MARK: - Verify Signature
    /// Verifies the signature of a received COSE message.
    /// - Parameters:
    ///   - detachedPayload: The optional detached payload.
    /// - Returns: `true` if the signature is valid, otherwise `false`.
    public func verifySignature(detachedPayload: Data? = nil) throws -> Bool {
        guard let alg = try self.getAttribute(for: CoseHeader.algorithm) as? CoseAlgorithm else {
            throw CoseError.invalidHeader("Algorithm attribute is missing or invalid")
        }

        try keyVerification(alg: alg, ops: .verify)

        return try alg.verify(
            key: self.key,
            data: createSigStructure(detachedPayload: detachedPayload),
            signature: signature
        )
    }

    // MARK: - Compute Signature
    /// Computes the signature over a COSE message.
    /// - Parameters:
    ///   - detachedPayload: The optional detached payload.
    /// - Returns: The computed signature as `Data`.
    public func computeSignature(detachedPayload: Data? = nil) throws -> Data {
        guard let alg = try self.getAttribute(for: CoseHeader.algorithm) as? CoseAlgorithm else {
            throw CoseError.invalidHeader("Algorithm attribute is missing or invalid")
        }

        try keyVerification(alg: alg, ops: .sign)

        return try alg.sign(
            key: self.key,
            data: createSigStructure(detachedPayload: detachedPayload)
        )
    }
}
