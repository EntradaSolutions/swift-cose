import Foundation
import PotentCBOR

/// COSE_Mac0 message type
public class Mac0Message: MacCommon {
    // MARK: - Properties
    public override var cborTag: Int {
        return 17
    }
    
    public var authTag: Data?

    // MARK: - Initialization
    public init(phdr: [String: CoseHeaderAttribute]? = nil,
                uhdr: [String: CoseHeaderAttribute]? = nil,
                payload: Data = Data(),
                externalAAD: Data = Data(),
                key: CoseKey? = nil,
                authTag: Data? = nil) throws {
        self.authTag = authTag
        try super.init(phdr: phdr, uhdr: uhdr, payload: payload, externalAAD: externalAAD, key: key)
    }

    // MARK: - Methods
    /// Decode a Mac0Message from a COSE object.
    /// - Parameters:
    ///   - coseObj: The COSE object represented as a CBOR array.
    ///   - allowUnknownAttributes: Flag to allow unknown attributes.
    /// - Returns: A decoded Mac0Message instance.
    public override class func fromCoseObj(_ coseObj: [CBOR]) throws -> Self {
        guard coseObj.count >= 3 else {
            throw CoseError.invalidMessage("COSE object must have at least 3 elements.")
        }

        let authTag = coseObj.last?.dataValue
        var obj = coseObj
        _ = obj.removeLast() // Remove authTag

        let instance = try super.fromCoseObj(obj) as! Mac0Message
        instance.authTag = authTag
        return instance
    }

    /// Encode and protect the COSE_Mac0 message.
    /// - Parameters:
    ///   - tag: Whether to include the CBOR tag.
    ///   - mac: Whether to compute the MAC tag.
    /// - Returns: The encoded message as `Data`.
    public func encode(tag: Bool = true, mac: Bool = true) throws -> Data {
        var message: [CBOR] = []
        
        message.append(phdrEncoded?.toCBOR ?? Data().toCBOR)
        message.append(uhdrEncoded?.toCBOR ?? Data().toCBOR)
        message.append(payload.toCBOR)
        
        if mac {
            guard let computedTag = computeTag() else {
                throw CoseError.invalidMessage("Unable to compute MAC tag.")
            }
            message.append(computedTag.toCBOR)
        }
        
        return try super.encode(message: message, tag: tag)
    }

    /// Compute the MAC tag (Placeholder: Implement your actual MAC computation logic).
    private func computeTag() -> Data? {
        // Replace this with actual MAC computation logic
        return "dummy_tag".data(using: .utf8)
    }

    public override var description: String {
        let phdrDescription = phdrEncoded?.description ?? "nil"
        let uhdrDescription = uhdrEncoded?.description ?? "nil"
        let payloadDescription = String(data: payload, encoding: .utf8) ?? "nil"
        let authTagDescription = authTag?.description ?? "nil"

        return "<Mac0Message: [phdr: \(phdrDescription), uhdr: \(uhdrDescription), payload: \(payloadDescription), authTag: \(authTagDescription)]>"
    }
}
