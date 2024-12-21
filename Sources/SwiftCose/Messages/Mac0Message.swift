import Foundation
import PotentCBOR

/// COSE_Mac0 message type
public class Mac0Message: MacCommon {
    // MARK: - Properties
    public override var context: String { "MAC0" }
    public override var cborTag: Int { 17 }

    // MARK: - Initialization
    public init(phdr: [CoseHeaderAttribute: Any]? = nil,
                uhdr: [CoseHeaderAttribute: Any]? = nil,
                payload: Data = Data(),
                externalAAD: Data = Data(),
                key: CoseSymmetricKey? = nil,
                authTag: Data? = nil) {
        super.init(phdr: phdr, uhdr: uhdr, payload: payload, externalAAD: externalAAD, key: key)
    }

    // MARK: - Methods
    /// Decode a Mac0Message from a COSE object.
    /// - Parameters:
    ///   - coseObj: The COSE object represented as a CBOR array.
    ///   - allowUnknownAttributes: Flag to allow unknown attributes.
    /// - Returns: A decoded Mac0Message instance.
    public override class func fromCoseObject(coseObj: inout [CBOR]) throws -> Mac0Message {
        guard let msg = try super.fromCoseObject(coseObj: &coseObj) as? Mac0Message else {
            throw CoseError.invalidMessage("Failed to decode base Mac0Message.")
        }

        // Pop the authTag from the COSE object
        guard let authTagData = coseObj.first else {
            throw CoseError.invalidMessage("Missing or invalid authTag.")
        }
        coseObj.removeFirst()
        msg.authTag = authTagData.bytesStringValue!
        
        return msg
    }

    /// Encode and protect the COSE_Mac0 message.
    /// - Parameters:
    ///   - tag: Whether to include the CBOR tag.
    ///   - mac: Whether to compute the MAC tag.
    /// - Returns: The encoded message as `Data`.
    public func encode(tag: Bool = true, mac: Bool = true) throws -> Data {
        var message: [CBOR] = []
        
        if mac {
            let computedTag = try self.computeTag()
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
        
        let result = try super.encode(message: message, tag: tag)
        
        return result
    }

    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let authTagDescription = truncate((authTag.base64EncodedString()))

        return "<Mac0Message: [phdr: \(phdr), uhdr: \(uhdr), payload: \(String(describing: payloadDescription)), authTag: \(authTagDescription)]>"
    }
}
