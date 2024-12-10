import Foundation
import PotentCBOR

/// EncMessage class for handling COSE_Encrypt messages.
public class EncMessage: EncCommon {
    public override var context: String { "Encrypt" }
    public override var cborTag: Int { 96 }
    
    public var recipients: [CoseRecipient] = []

    // MARK: - Initialization
    public required init(phdr: [String: CoseHeaderAttribute]? = nil,
                         uhdr: [String: CoseHeaderAttribute]? = nil,
                         payload: Data = Data(),
                         externalAAD: Data = Data(),
                         key: CoseKey? = nil,
                         recipients: [CoseRecipient]? = nil) throws {
        try super.init(phdr: phdr, uhdr: uhdr, payload: payload, externalAAD: externalAAD, key: key)
        self.recipients = recipients ?? []
    }

    // MARK: - Encoding
    public func encode(tag: Bool = true, encrypt: Bool = true) throws -> Data {
        var message: [CBOR] = []
        
        // Encode headers and payload
        if encrypt {
            message = [phdrEncoded?.toCBOR ?? CBOR.null, uhdrEncoded?.toCBOR ?? CBOR.null, try self.encrypt()]
        } else {
            message = [phdrEncoded?.toCBOR ?? CBOR.null, uhdrEncoded?.toCBOR ?? CBOR.null, self.payload.toCBOR]
        }
        
        // Append recipients
        if !recipients.isEmpty {
            let recipientData = try recipients.map { try $0.encode(targetAlg: self.getHeaderAttribute(.algorithm)) }
            message.append(CBOR.array(recipientData))
        }
        
        return try super.encode(message: message, tag: tag)
    }
    
    // MARK: - Encryption
    public func encrypt() throws -> Data {
        let targetAlgorithm = try self.getHeaderAttribute(.algorithm) as Algorithm
        let recipientTypes = try CoseRecipient.verifyRecipients(recipients)
        
        if recipientTypes.contains(DirectEncryption.self) {
            return try super.encrypt()
        } else if recipientTypes.contains(DirectKeyAgreement.self) {
            self.key = try recipients.first?.computeCEK(algorithm: targetAlgorithm, usage: "encrypt")
            return try super.encrypt()
        } else if recipientTypes.contains(KeyWrap.self) || recipientTypes.contains(KeyAgreementWithKeyWrap.self) {
            var keyBytes = Data(count: targetAlgorithm.keyLength)
            _ = keyBytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, keyBytes.count, $0.baseAddress!) }
            
            for recipient in recipients {
                if recipient.payload.isEmpty {
                    recipient.payload = keyBytes
                } else {
                    keyBytes = recipient.payload
                }
                try recipient.encrypt(algorithm: targetAlgorithm)
            }
            
            self.key = SymmetricKey(k: keyBytes, optionalParams: [KpAlg: targetAlgorithm, KpKeyOps: [.encrypt]])
            return try super.encrypt()
        } else {
            throw CoseError.unsupportedRecipientType("Unsupported COSE recipient class")
        }
    }

    // MARK: - Decryption
    public func decrypt(recipient: CoseRecipient) throws -> Data {
        let targetAlgorithm = try self.getHeaderAttribute(.algorithm) as Algorithm
        
        guard CoseRecipient.hasRecipient(recipient, in: recipients) else {
            throw CoseError.recipientNotFound("Recipient not found")
        }
        
        let recipientTypes = try CoseRecipient.verifyRecipients(recipients)
        
        if recipientTypes.contains(DirectEncryption.self) {
            return try super.decrypt()
        } else if recipientTypes.contains(DirectKeyAgreement.self) || recipientTypes.contains(KeyWrap.self) || recipientTypes.contains(KeyAgreementWithKeyWrap.self) {
            self.key = try recipient.computeCEK(algorithm: targetAlgorithm, usage: "decrypt")
            return try super.decrypt()
        } else {
            throw CoseError.unsupportedRecipientType("Unsupported COSE recipient class")
        }
    }
    
    // MARK: - Representation
    public override var description: String {
        let phdrDesc = phdr?.description ?? "nil"
        let uhdrDesc = uhdr?.description ?? "nil"
        let recipientsDesc = recipients.map { $0.description }.joined(separator: ", ")
        return "<EncMessage: [\(phdrDesc), \(uhdrDesc), \(payload), [\(recipientsDesc)]]>"
    }
}
