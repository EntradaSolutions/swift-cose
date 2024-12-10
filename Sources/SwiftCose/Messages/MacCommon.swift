import Foundation
import PotentCBOR

/// Abstract base class for COSE Mac messages (e.g., COSE_Mac and COSE_Mac0)
public class MacCommon: CoseMessage {

    // MARK: - Properties
    /// Abstract property to get the context of the message.
    public var context: String {
        fatalError("context must be implemented in subclasses.")
    }

    public var authTag: Data = Data()

    // MARK: - Initialization
    public override init(phdr: [String: CoseHeaderAttribute]? = nil,
                         uhdr: [String: CoseHeaderAttribute]? = nil,
                         payload: Data? = nil,
                         externalAAD: Data = Data(),
                         key: CoseKey? = nil) throws {
        try super.init(phdr: phdr, uhdr: uhdr, payload: payload, externalAAD: externalAAD, key: key)
    }

    // MARK: - Methods
    /// Verifies the authentication tag of a received message.
    /// - Throws: `CoseError` if verification fails.
    /// - Returns: A Boolean indicating whether the verification succeeded.
    public func verifyTag() throws -> Bool {
        guard let alg = self.getAttribute(forKey: .algorithm) else {
            throw CoseError.invalidMessage("Algorithm is not set in the headers.")
        }

        guard let key = self.key as? SymmetricKey else {
            throw CoseError.invalidKey("Key must be of type SymmetricKey.")
        }

        try key.verifyKeyUsage(algorithm: alg, operations: [.macVerify])

        return try alg.verifyTag(key: key, tag: self.authTag, data: self.macStructure)
    }

    /// Computes the authentication tag of a COSE_Mac or COSE_Mac0 message.
    /// - Throws: `CoseError` if the tag computation fails.
    /// - Returns: The computed authentication tag as `Data`.
    public func computeTag() throws -> Data {
        guard let alg = self.getAttribute(forKey: .algorithm) else {
            throw CoseError.invalidMessage("Algorithm is not set in the headers.")
        }

        guard let key = self.key as? SymmetricKey else {
            throw CoseError.invalidKey("Key must be of type SymmetricKey.")
        }

        try key.verifyKeyUsage(algorithm: alg, operations: [.macCreate])

        self.authTag = try alg.computeTag(key: key, data: self.macStructure)
        return self.authTag
    }

    /// Creates the mac_structure that needs to be MAC'ed.
    /// - Throws: `CoseError` if the structure cannot be created.
    /// - Returns: A serialized CBOR representation of the mac structure.
    public var macStructure: Data {
        get throws {
            guard let payload = self.payload else {
                throw CoseError.invalidMessage("Payload cannot be empty for tag computation.")
            }

            var macStructure: [CBOR] = [CBOR.utf8String(context)]
            self.baseStructure(&macStructure)
            macStructure.append(payload.toCBOR)

            return try CBORSerialization.data(from: CBOR.array(macStructure))
        }
    }

    // MARK: - Helpers
    /// Retrieves an attribute from the protected or unprotected headers.
    /// - Parameter key: The key for the attribute.
    /// - Returns: The attribute if found, or nil.
    private func getAttribute(forKey key: CoseHeaderAttribute) -> CoseAlgorithm? {
        if let phdrValue = phdr?[key], let alg = phdrValue as? CoseAlgorithm {
            return alg
        }
        if let uhdrValue = uhdr?[key], let alg = uhdrValue as? CoseAlgorithm {
            return alg
        }
        return nil
    }
}
