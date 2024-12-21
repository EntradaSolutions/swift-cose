import Foundation
import PotentCBOR

public class DirectEncryption: CoseRecipient {
    
    // MARK: - Properties
    public override var context: String {
        get { return _context }
        set { _context = newValue }
    }
    private var _context: String = ""

    // MARK: - Methods
    public override class func fromCoseObject(coseObj: inout [CBOR], context: String? = nil) throws -> DirectEncryption {
        
        let msg = try super.fromCoseObject(
            coseObj: &coseObj
        ) as! DirectEncryption
        
        // Set context if provided
        if let ctx = context {
            msg.context = ctx
        }
        
        // Check for zero-length payload
        guard let payload = msg.payload, payload.isEmpty else {
            throw CoseError.malformedMessage("Recipient class DIRECT_ENCRYPTION must have a zero-length ciphertext.")
        }
        
        // Ensure there are no recipients
        guard msg.recipients.isEmpty else {
            throw CoseError.malformedMessage("Recipient class DIRECT_ENCRYPTION cannot carry other recipients.")
        }
        
        // Validate algorithm and protected header
        guard let alg = try msg.getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Algorithm not found in protected headers")
        }
        
        if CoseAlgorithmIdentifier.fromFullName(alg.fullname) == .direct && !msg.phdr.isEmpty {
            throw CoseError.malformedMessage(
                "Recipient class DIRECT_ENCRYPTION with alg \(alg) must have a zero-length protected header."
            )
        }
        
        return msg
    }
    
    // Encoding logic for DirectEncryption
    public override func encode(targetAlgorithm: CoseAlgorithm? = nil) throws -> [Any] {
        guard let alg = try getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Message must carry an algorithm parameter when using DIRECT_ENCRYPTION mode.")
        }
        
        if CoseAlgorithmIdentifier.fromFullName(alg.fullname) == .direct && !phdr.isEmpty {
            throw CoseError.malformedMessage("Protected header must be empty.")
        }

        if !recipients.isEmpty {
            throw CoseError.invalidMessage("Recipient class DIRECT_ENCRYPTION cannot carry recipients.")
        }

        return [
            phdrEncoded,
            uhdrEncoded,
            Data()
        ]
    }

    // Compute Content Encryption Key (CEK)
    public override func computeCEK(targetAlgorithm: CoseAlgorithm, ops: String) throws -> CoseSymmetricKey? {
        guard let alg = try getAttr(Algorithm()) as? CoseAlgorithm else {
            throw CoseError.invalidAlgorithm("Message must carry an algorithm parameter when using DIRECT_ENCRYPTION mode.")
        }
        
        if CoseAlgorithmIdentifier.fromFullName(alg.fullname) == .direct && !phdr.isEmpty {
            return nil
        } else {
            guard let key = key else {
                throw CoseError.invalidKey("No key available for deriving CEK.")
            }
            
            try key.verify(
                keyType: CoseSymmetricKey.self,
                algorithm: targetAlgorithm,
                keyOps: [DeriveKeyOp(), DeriveBitsOp()]
            )
            throw CoseError.notImplemented("Derivation for target algorithm is not yet implemented.")
        }
    }

    // Debug description
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let recipientsDescription = recipients.map { $0.description }.joined(separator: ", ")

        return "<COSE_Recipient: [\(phdr), \(uhdr), \(payloadDescription), \(recipientsDescription)]>"
    }
}
