import Foundation

public class DirectKeyAgreement: CoseRecipient {

    // Class method to create an instance from a COSE object
    public override class func createRecipient(from coseObj: [CBOR], allowUnknownAttributes: Bool, context: String) throws -> DirectKeyAgreement {
        let msg = try super.createRecipient(from: coseObj, allowUnknownAttributes: allowUnknownAttributes, context: context) as! DirectKeyAgreement
        let alg = msg.getAttr(for: .algorithm)

        if [EcdhEsHKDF256.self, EcdhEsHKDF512.self].contains(where: { $0 == type(of: alg) }),
           msg.getAttr(for: .ephemeralKey) == nil {
            throw CoseError.malformedMessage("Recipient must carry an ephemeral COSE key object.")
        }

        if !msg.recipients.isEmpty {
            throw CoseError.malformedMessage("Recipient cannot carry additional recipients.")
        }

        return msg
    }

    // Context property
    private var _context: String = ""
    public var context: String {
        get { _context }
        set { _context = newValue }
    }

    // Encoding logic
    public override func encode(targetAlg: CoseAlgorithm) throws -> [CBOR] {
        guard let alg = getAttr(for: .algorithm) else {
            throw CoseError.malformedMessage("The algorithm parameter should be included in either the protected or unprotected header.")
        }

        // Static receiver key
        guard let peerKey = localAttributes[.staticKey] as? EC2Key else {
            throw CoseError.invalidKey("Static receiver key cannot be nil. It should be configured in 'localAttributes' of the message.")
        }

        // Ephemeral key generation
        if key == nil {
            if [EcdhEsHKDF256.self, EcdhEsHKDF512.self].contains(where: { $0 == type(of: alg) }) {
                try setupEphemeralKey(peerKey: peerKey)
            } else {
                throw CoseError.invalidKey("Static sender key cannot be nil.")
            }
        }

        if recipients.count > 1 {
            throw CoseError.malformedMessage("DIRECT_KEY_AGREEMENT cannot carry additional recipients.")
        }

        if getAttr(for: .ephemeralKey) == nil,
           [EcdhEsHKDF256.self, EcdhEsHKDF512.self].contains(where: { $0 == type(of: alg) }) {
            throw CoseError.malformedMessage("DIRECT_KEY_AGREEMENT must carry an ephemeral COSE key object.")
        }

        var encoded: [CBOR] = []
        encoded.append(phdrEncoded?.toCBOR ?? CBOR.null)
        encoded.append(uhdrEncoded?.toCBOR ?? CBOR.null)
        encoded.append(CBOR.byteString(payload))

        if !recipients.isEmpty {
            let encodedRecipients = try recipients.map { try $0.encode() }
            encoded.append(CBOR.array(encodedRecipients))
        }

        return encoded
    }

    // Compute KEK logic
    private func computeKek(targetAlg: CoseAlgorithm, peerKey: EC2Key, localKey: EC2Key, kexAlg: CoseAlgorithm) throws -> Data {
        guard let derivedKey = kexAlg.deriveKek(crv: peerKey.crv, localKey: localKey, peerKey: peerKey, context: try getKdfContext(targetAlg)) else {
            throw CoseError.keyDerivationFailed("Failed to derive KEK.")
        }
        return derivedKey
    }

    // Compute CEK logic
    public override func computeCEK(targetAlgorithm: CoseAlgorithm) throws -> Data {
        guard let alg = getAttr(for: .algorithm) else {
            throw CoseError.unsupportedAlgorithm("Unsupported algorithm for \(type(of: self)).")
        }

        let peerKey: EC2Key
        if [EcdhSsHKDF256.self, EcdhSsHKDF512.self, EcdhEsHKDF256.self, EcdhEsHKDF512.self].contains(where: { $0 == type(of: alg) }) {
            if let staticKey = localAttributes[.staticKey] as? EC2Key {
                peerKey = staticKey
            } else {
                throw CoseError.invalidKey("Unknown static receiver public key.")
            }
        } else {
            throw CoseError.unsupportedAlgorithm("Unsupported algorithm for \(type(of: self)).")
        }

        try peerKey.verifyKey(type: EC2Key.self, algorithm: alg, operations: [.deriveKey, .deriveBits])
        try key?.verifyKey(type: EC2Key.self, algorithm: alg, operations: [.deriveKey, .deriveBits])

        return try computeKek(targetAlg: targetAlgorithm, peerKey: peerKey, localKey: key!, kexAlg: alg)
    }

    // String representation
    public override var description: String {
        let phdrRepr = phdrEncoded?.description ?? "nil"
        let uhdrRepr = uhdrEncoded?.description ?? "nil"
        return "<COSE_Recipient: [\(phdrRepr), \(uhdrRepr), \(payload.count) bytes, \(recipients)]>"
    }

    // Ephemeral key setup (placeholder for actual implementation)
    private func setupEphemeralKey(peerKey: EC2Key) throws {
        // Ephemeral key generation logic here
    }
}
