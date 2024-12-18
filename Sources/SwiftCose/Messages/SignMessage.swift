import Foundation
import PotentCBOR

/// Abstract class representing a COSE Sign Message.
public class SignMessage: CoseMessage {
    
    // MARK: - Properties
    public var context: String {
        return "Signature"
    }
    
    public var signers: [CoseSignature] = []
    
    // MARK: - Initialization
    public init(
        phdr: [String: CoseHeaderAttribute]? = nil,
        uhdr: [String: CoseHeaderAttribute]? = nil,
        payload: Data? = nil,
        signers: [CoseSignature] = []
    ) throws {
        try super.init(phdr: phdr, uhdr: uhdr, payload: payload)
        self.signers = signers
        self.signers.forEach { $0.parent = self }
    }
    
    // MARK: - Methods
    /// Decodes a COSE_Sign message from a CBOR object.
    /// - Parameters:
    ///   - coseObj: The CBOR object to decode.
    ///   - allowUnknownAttributes: Whether to allow unknown attributes.
    /// - Returns: The decoded SignMessage.
    public class func fromCoseObj(_ coseObj: [CBOR], allowUnknownAttributes: Bool = false) throws -> SignMessage {
        guard let payload = coseObj.first?.dataValue else {
            throw CoseError.invalidMessage("Invalid COSE object.")
        }
        
        var remainingCoseObj = coseObj
        remainingCoseObj.removeFirst() // Remove payload
        
        var signers: [CoseSignature] = []
        if let signerArray = remainingCoseObj.first?.arrayValue {
            signers = try signerArray.map { signerCbor in
                try CoseSignature.fromCoseObj([signerCbor], allowUnknownAttributes: allowUnknownAttributes)
            }
        }
        
        return try SignMessage(phdr: nil, uhdr: nil, payload: payload.toData, signers: signers)
    }
    
    /// Encodes the message to CBOR.
    /// - Parameters:
    ///   - tag: Whether to include a CBOR tag.
    ///   - detachedPayload: An optional detached payload.
    /// - Returns: The encoded message as Data.
    public func encode(tag: Bool = true, detachedPayload: Data? = nil) throws -> Data {
        var message: [CBOR] = []
        message.append(phdrEncoded?.toCBOR ?? Data().toCBOR)
        message.append(uhdrEncoded?.toCBOR ?? Data().toCBOR)
        message.append(payload?.toCBOR ?? CBOR.null)
        
        if !signers.isEmpty {
            let encodedSigners = try signers.map { try $0.encode(detachedPayload: detachedPayload) }
            message.append(.array(encodedSigners))
        }
        
        if tag {
            return try CBORSerialization.data(from: .tagged(CBOR.Tag(rawValue: self.cborTag), .array(message)))
        } else {
            return try CBORSerialization.data(from: .array(message))
        }
    }
    
    // MARK: - Description
//    public var description: String {
//        let phdrDescription = phdr?.description ?? "nil"
//        let uhdrDescription = uhdr?.description ?? "nil"
//        let payloadDescription = payload?.base64EncodedString() ?? "nil"
//        let signersDescription = signers.map { $0.description }.joined(separator: ", ")
//        return "<COSE_Sign: [\(phdrDescription), \(uhdrDescription), \(payloadDescription), [\(signersDescription)]]>"
//    }
}
