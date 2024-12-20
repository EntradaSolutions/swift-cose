import Foundation

/// KeyWrap recipient type
public class KeyWrap: CoseRecipient {
    
    // MARK: - Initialization
    
    public required init(fromCoseObj coseObj: [CBOR], allowUnknownAttributes: Bool) throws {
        try super.init(fromCoseObj: coseObj)
        
        self.context = "DefaultContext" // Default context value
        
        guard let alg = self.phdr[.algorithm] ?? self.uhdr[.algorithm] else {
            throw CoseError.malformedMessage("Recipient class KEY_WRAP must have a valid algorithm in its header.")
        }
        
        if let algorithm = alg as? CoseAlgorithm, [.A128KW, .A192KW, .A256KW].contains(algorithm), !phdr.isEmpty {
            throw CoseError.malformedMessage("Recipient class KEY_WRAP with algorithm \(algorithm) must have an empty protected header.")
        }
        
        if self.payload.isEmpty {
            throw CoseError.malformedMessage("Recipient class KEY_WRAP must carry the encrypted CEK in its payload.")
        }
        
        self.recipients = try coseObj.dropFirst(3).compactMap {
            try CoseRecipient.createRecipient(from: $0.arrayValue ?? [], allowUnknownAttributes: allowUnknownAttributes, context: "Rec_Recipient")
        }
    }
    
    // MARK: - Properties
    
    private var _context: String = ""
    public var context: String {
        get { return _context }
        set { _context = newValue }
    }
    
    // MARK: - Encoding
    
    public override func encode() throws -> [CBOR] {
        var recipient: [CBOR] = [
            self.phdrEncoded?.toCBOR ?? CBOR.null,
            self.uhdrEncoded?.toCBOR ?? CBOR.null,
            try self.encrypt(targetAlg: self.getAlgorithm())
        ]
        
        if !recipients.isEmpty {
            recipient.append(CBOR.array(try recipients.map { try $0.encode() }))
        }
        
        return recipient
    }
    
    // MARK: - Key Management
    
    private func computeKek(targetAlgorithm: CoseAlgorithm, ops: String) throws -> Data {
        guard let algorithm = self.getAlgorithm() else {
            throw CoseError.invalidRecipientConfiguration("Algorithm not found.")
        }
        
        if key == nil {
            if recipients.isEmpty {
                throw CoseError.keyUnavailable("No key found to \(ops) the CEK.")
            } else {
                let recipientTypes = try CoseRecipient.verifyRecipients(recipients)
                
                if ops == "encrypt" {
                    if recipientTypes.contains(DirectKeyAgreement.self) {
                        key = try recipients.first!.computeCek(targetAlgorithm: targetAlg)
                    } else if recipientTypes.contains(KeyWrap.self) || recipientTypes.contains(KeyAgreementWithKeyWrap.self) {
                        let keyBytes = Data.randomBytes(ofLength: algorithm.keyLength)
                        for recipient in recipients {
                            recipient.payload = keyBytes
                        }
                        key = SymmetricKey(data: keyBytes)
                    } else {
                        throw CoseError.unsupportedRecipientType("Unsupported COSE recipient class.")
                    }
                } else {
                    if recipientTypes.contains(DirectKeyAgreement.self) || recipientTypes.contains(KeyWrap.self) || recipientTypes.contains(KeyAgreementWithKeyWrap.self) {
                        key = try recipients.first!.decrypt(targetAlgorithm: targetAlg)
                    } else {
                        throw CoseError.unsupportedRecipientType("Unsupported COSE recipient class.")
                    }
                }
            }
        }
        
        guard let key = self.key else {
            throw CoseError.keyUnavailable("No key found to decrypt the CEK.")
        }
        
        return key.data
    }
    
    public override func computeCEK(targetAlgorithm: CoseAlgorithm) throws -> Data {
        if payload.isEmpty {
            throw CoseError.keyUnavailable("Encrypted CEK not found.")
        }
        return payload
    }
    
    public func encrypt(targetAlg: CoseAlgorithm) throws -> Data {
        guard let algorithm = getAlgorithm() else {
            throw CoseError.invalidRecipientConfiguration("Algorithm parameter must be specified.")
        }
        
        switch algorithm {
        case .A128KW, .A192KW, .A256KW:
            let kek = SymmetricKey(data: try computeKek(targetAlg: targetAlg, ops: "encrypt"))
            return try algorithm.keyWrap(keyEncryptionKey: kek, plaintext: payload)
        case .RsaesOaepSha512, .RsaesOaepSha256, .RsaesOaepSha1:
            guard let key = self.key as? RSAKey else {
                throw CoseError.invalidKey("Invalid RSA key for encryption.")
            }
            return try algorithm.keyWrap(keyEncryptionKey: key, plaintext: payload)
        default:
            throw CoseError.unsupportedAlgorithm("Algorithm \(algorithm) is not supported for KeyWrap.")
        }
    }
    
    public func decrypt(targetAlg: CoseAlgorithm) throws -> Data {
        guard let algorithm = getAlgorithm() else {
            throw CoseError.invalidRecipientConfiguration("Algorithm parameter must be specified.")
        }
        
        switch algorithm {
        case .A128KW, .A192KW, .A256KW:
            let kek = SymmetricKey(data: try computeKek(targetAlg: targetAlg, ops: "decrypt"))
            return try algorithm.keyUnwrap(keyEncryptionKey: kek, ciphertext: payload)
        case .RsaesOaepSha512, .RsaesOaepSha256, .RsaesOaepSha1:
            guard let key = self.key as? RSAKey else {
                throw CoseError.invalidKey("Invalid RSA key for decryption.")
            }
            return try algorithm.keyUnwrap(keyEncryptionKey: key, ciphertext: payload)
        default:
            throw CoseError.unsupportedAlgorithm("Algorithm \(algorithm) is not supported for KeyWrap.")
        }
    }
    
    // MARK: - Debug Description
    
    public override var description: String {
        let phdrDescription = phdr.map { "\($0)" } ?? "null"
        let uhdrDescription = uhdr.map { "\($0)" } ?? "null"
        let recipientsDescription = recipients.map { "\($0)" }.joined(separator: ", ")
        
        return "<COSE_Recipient: [\(phdrDescription), \(uhdrDescription), \(payload), [\(recipientsDescription)]]>"
    }
}
