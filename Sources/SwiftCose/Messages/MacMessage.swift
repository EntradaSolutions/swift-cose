import Foundation
import PotentCBOR

/// COSE MACed Message with Recipients
public class MacMessage: MacCommon {
    // MARK: - Properties
    public override var context: String { "MAC" }
    public override var cborTag: Int { 97 }
    public var recipients: [CoseRecipient] = []
    
    // MARK: - Initialization
    public init(phdr: [String: CoseHeaderAttribute]? = nil,
                uhdr: [String: CoseHeaderAttribute]? = nil,
                payload: Data = Data(),
                externalAAD: Data = Data(),
                key: CoseSymmetricKey? = nil,
                recipients: [CoseRecipient] = []) {
        super.init(phdr: phdr,
                   uhdr: uhdr,
                   payload: payload,
                   externalAAD: externalAAD,
                   key: key)
        self.recipients = recipients
    }
    
    // MARK: - Methods
    public override class func fromCoseObject(coseObj: inout [Any]) throws -> MacMessage {
        guard let msg = try super.fromCoseObject(coseObj: &coseObj) as? MacMessage else {
            throw CoseError.invalidMessage("Failed to decode base EncMessage.")
        }
        
        // Extract and assign the authentication tag
        if !coseObj.isEmpty {
            msg.authTag = (coseObj.removeFirst() as? Data)!
        } else {
            throw CoseError.valueError("Missing authentication tag in COSE object.")
        }

        // Attempt to decode recipients
        do {
            if let recipientArray = coseObj.first as? [Any] {
                coseObj.removeFirst()
                let recipients = try recipientArray.map {
                    try CoseRecipient.createRecipient(from: $0, allowUnknownAttributes: true, context: "Mac_Recipient")
                }
                msg.recipients = recipients
            } else {
                msg.recipients = [] // No recipients present
            }
        } catch {
            throw CoseError.valueError("Failed to decode recipients.")
        }

        return msg
    }
    
    /// Encodes and protects the COSE_Mac message.
    /// - Parameters:
    ///   - tag: The boolean value which indicates if the COSE message will have a CBOR tag.
    ///   - mac: The boolean value which activates or deactivates the MAC tag.
    /// - Returns: The CBOR-encoded COSE Mac message.
    public func encode(tag: Bool = true, mac: Bool = true) throws -> Data {
        var message: [CBOR] = []
        
        if mac {
            let computedTag = self.computeTag()
            message = [
                phdrEncoded.toCBOR,
                CBOR.fromAny(uhdrEncoded),
                payload?.toCBOR ?? CBOR.null,
                computedTag.toCBOR]
        } else {
            message = [
                phdrEncoded.toCBOR,
                CBOR.fromAny(uhdrEncoded),
                payload?.toCBOR ?? CBOR.null]
        }
        
        if !self.recipients.isEmpty {
            guard let alg = try getAttr(Algorithm()) as? CoseAlgorithm else {
                throw CoseError.invalidAlgorithm("Algorithm not found in headers")
            }
            
            let recipientData = try recipients.map {
                try $0
                    .encode(
                        targetAlg: alg
                    ).toCBOR
            }
            message.append(CBOR.array(recipientData))
        }
        
        let result = try super.encode(message: message, tag: tag)
        
        return result
    }
    
    public override func computeTag() throws -> Data {
        guard let targetAlgorithm = try? getAttr(Algorithm()) as? EncAlgorithm else {
            fatalError("Algorithm not found in headers")
        }

        let recipientTypes = try! CoseRecipient.verifyRecipients(recipients)

        if recipientTypes.contains(where: { $0 is DirectEncryption }) {
            // Key should already be known
            return try super.computeTag()
        } else if recipientTypes.contains(where: { $0 is DirectKeyAgreement }) {
            self.key = try! recipients.first?.computeCEK(targetAlgorithm: targetAlgorithm, ops: "encrypt")
            return try super.computeTag()
        } else if recipientTypes.contains(where: { $0 is KeyWrap }) || recipientTypes.contains(where: { $0 is KeyAgreementWithKeyWrap }) {
            // Generate random key bytes
            var keyBytes = Data(count: targetAlgorithm.keyLength!)
            _ = keyBytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, keyBytes.count, $0.baseAddress!) }
            
            for recipient in recipients {
                if recipient.payload?.isEmpty ?? true {
                    recipient.payload = keyBytes
                } else {
                    keyBytes = recipient.payload!
                }
                if let recipient = recipient as? KeyAgreementWithKeyWrap {
                    let _ = try recipient.encrypt(targetAlgorithm: targetAlgorithm)
                } else if let recipient = recipient as? KeyWrap {
                    let _ = try recipient.encrypt(targetAlg: targetAlgorithm)
                } else {
                    throw CoseError.unsupportedRecipient("Unsupported COSE recipient class")
                }
            }

            self.key = try! CoseSymmetricKey(
                k: keyBytes,
                optionalParams: [
                    KpAlg(): targetAlgorithm,
                    KpKeyOps(): [MacCreateOp()]
                ]
            )
            return try super.computeTag()
        } else {
            throw CoseError.unsupportedRecipient("Unsupported COSE recipient class")
        }
    }
    
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let recipientsDesc = recipients.map { $0.description }.joined(separator: ", ")
        let authTagDescription = truncate((authTag.base64EncodedString()))
        let recipientsDescription = recipients.map { $0.description }.joined(separator: ", ")
        return "<COSE_Mac: [\(phdr), \(uhdr), \(payloadDescription), \(authTagDescription), [\(recipientsDescription)]]>"
    }
}
