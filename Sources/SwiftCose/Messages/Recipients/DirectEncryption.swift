import Foundation

public class DirectEncryption: CoseRecipient {

    // Custom initializer for DirectEncryption
    public required init(fromCoseObj coseObj: [CBOR]) throws {
        try super.init(fromCoseObj: coseObj)
        
        // Set context if provided
        if let context = coseObj[safe: 4]?.stringValue {
            self.context = context
        }

        // Ensure payload is zero-length
        guard payload.isEmpty else {
            throw CoseError.malformedMessage("Recipient class DIRECT_ENCRYPTION must have a zero-length ciphertext.")
        }

        // Ensure there are no nested recipients
        guard recipients.isEmpty else {
            throw CoseError.malformedMessage("Recipient class DIRECT_ENCRYPTION cannot carry other recipients.")
        }

        // Validate algorithm and protected header
        if let algorithm = phdr?[CoseHeaderAttribute.algorithm],
           algorithm == .direct,
           !phdr!.isEmpty {
            throw CoseError.malformedMessage(
                "Recipient class DIRECT_ENCRYPTION with alg \(algorithm) must have a zero-length protected header."
            )
        }
    }

    // Property for context
    private var _context: String = ""
    public var context: String {
        get { return _context }
        set { _context = newValue }
    }

    // Encoding logic for DirectEncryption
    public override func encode() throws -> [CBOR] {
        guard let algorithm = phdr?[CoseHeaderAttribute.algorithm] else {
            throw CoseError.invalidMessage("Message must carry an algorithm parameter when using DIRECT_ENCRYPTION mode.")
        }

        if algorithm == .direct && !phdr!.isEmpty {
            throw CoseError.invalidMessage("Protected header must be empty.")
        }

        if !recipients.isEmpty {
            throw CoseError.invalidMessage("Recipient class DIRECT_ENCRYPTION cannot carry recipients.")
        }

        return [
            phdrEncoded?.toCBOR ?? CBOR.null,
            uhdrEncoded?.toCBOR ?? CBOR.null,
            CBOR.byteString(Data())
        ]
    }

    // Compute Content Encryption Key (CEK)
    public override func computeCEK(targetAlgorithm: CoseAlgorithm) throws -> Data? {
        guard let algorithm = phdr?[CoseHeaderAttribute.algorithm] else {
            throw CoseError.invalidMessage("Algorithm is missing in recipient.")
        }

        if algorithm == .direct {
            return nil
        } else {
            guard let key = key else {
                throw CoseError.invalidKey("No key available for deriving CEK.")
            }

            try key.verify(type: SymmetricKey.self, algorithm: algorithm, keyOps: [.deriveKey, .deriveBits])
            // Placeholder for unsupported functionality
            throw CoseError.unimplemented("Derivation for target algorithm is not yet implemented.")
        }
    }

    // Debug description
    public override var description: String {
        let phdrRepr = phdr?.description ?? "nil"
        let uhdrRepr = uhdr?.description ?? "nil"
        let recipientsRepr = recipients.description
        let payloadRepr = payload.base64EncodedString()

        return "<COSE_Recipient: [\(phdrRepr), \(uhdrRepr), \(payloadRepr), \(recipientsRepr)]>"
    }
}
