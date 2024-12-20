import Foundation

public class KeyAgreementWithKeyWrap: CoseRecipient {
    
    public var context: String = ""
    
    public required init(fromCoseObj coseObj: [CBOR]) throws {
        try super.init(fromCoseObj: coseObj)
        if self.payload.isEmpty {
            throw CoseError.invalidMessage("Recipient class KEY_AGREEMENT_WITH_KEY_WRAP must carry the encrypted CEK in its payload.")
        }
        self.recipients = try coseObj.last?.arrayValue?.map {
            try CoseRecipient.createRecipient(from: $0.arrayValue ?? [], allowUnknownAttributes: true, context: "Rec_Recipient")
        } ?? []
    }
    
    public override func computeCEK(targetAlgorithm: CoseAlgorithm) throws -> Data {
        if let _ = self.payload as? Data, !self.payload.isEmpty {
            return self.payload
        } else {
            return try self.decrypt(targetAlgorithm: targetAlgorithm)
        }
    }
    
    public override func encode() throws -> [CBOR] {
        var recipient: [CBOR] = []
        recipient.append(phdrEncoded?.toCBOR ?? CBOR.null)
        recipient.append(uhdrEncoded?.toCBOR ?? CBOR.null)
        recipient.append(CBOR.byteString(try encrypt(targetAlgorithm: getAlgorithm())))
        
        if !recipients.isEmpty {
            let encodedRecipients = try recipients.map { try $0.encode() }
            recipient.append(CBOR.array(encodedRecipients))
        }
        return recipient
    }
    
    private func computeKek(targetAlgorithm: CoseAlgorithm, peerKey: CoseKey, localKey: CoseKey, kexAlgorithm: CoseAlgorithm) throws -> Data {
        return try kexAlgorithm.deriveKek(crv: peerKey.crv, localKey: localKey, peerKey: peerKey, kdfContext: getKdfContext(targetAlgorithm))
    }
    
    public func encrypt(targetAlgorithm: CoseAlgorithm) throws -> Data {
        guard let peerKey = localAttributes[.staticKey] as? CoseKey else {
            throw CoseError.invalidMessage("Static receiver key cannot be nil.")
        }
        
        guard let algorithm = getAlgorithm() else {
            throw CoseError.invalidMessage("Algorithm must be included in the unprotected header.")
        }
        
        if key == nil {
            if [.ecdhEsA128KW, .ecdhEsA192KW, .ecdhEsA256KW].contains(algorithm) {
                try setupEphemeralKey(peerKey: peerKey)
            } else {
                throw CoseError.invalidMessage("Static sender key cannot be nil.")
            }
        }
        
        let keyBytes = try computeKek(targetAlgorithm: algorithm.getKeyWrapFunc(), peerKey: peerKey, localKey: key!, kexAlgorithm: algorithm)
        let wrapFunc = algorithm.getKeyWrapFunc()
        return try wrapFunc.keyWrap(key: SymmetricKey(k: keyBytes), payload: payload)
    }
    
    public func decrypt(targetAlgorithm: CoseAlgorithm) throws -> Data {
        guard let algorithm = getAlgorithm() else {
            throw CoseError.unsupportedAlgorithm("Unsupported algorithm.")
        }
        
        let peerKey: CoseKey
        if [.ecdhEsA128KW, .ecdhEsA192KW, .ecdhEsA256KW].contains(algorithm) {
            guard let ephemeralKey = getAttribute(.ephemeralKey) as? CoseKey else {
                throw CoseError.invalidMessage("Ephemeral key is required.")
            }
            peerKey = ephemeralKey
        } else if [.ecdhSsA128KW, .ecdhSsA192KW, .ecdhSsA256KW].contains(algorithm) {
            guard let staticKey = getAttribute(.staticKey) as? CoseKey else {
                throw CoseError.invalidMessage("Static key is required.")
            }
            peerKey = staticKey
        } else {
            throw CoseError.unsupportedAlgorithm("Unsupported algorithm.")
        }
        
        let kek = try SymmetricKey(k: computeKek(targetAlgorithm: algorithm.getKeyWrapFunc(), peerKey: peerKey, localKey: key!, kexAlgorithm: algorithm))
        return try algorithm.getKeyWrapFunc().keyUnwrap(key: kek, payload: payload)
    }
    
    private func getKdfContext(_ targetAlgorithm: CoseAlgorithm) -> Data {
        // Implement the logic to generate KDF context as required
        return Data()
    }
    
    private func setupEphemeralKey(peerKey: CoseKey) throws {
        // Implement the logic to setup an ephemeral key pair
    }
}
