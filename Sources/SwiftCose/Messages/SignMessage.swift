import Foundation
import PotentCBOR

/// Abstract class representing a COSE Sign Message.
public class CoseSignMessage: CoseMessage {
    
    // MARK: - Abstract Properties
    public var context: String {
        fatalError("Subclasses must implement the 'context' property")
    }
    
    // MARK: - Properties
    
    /// The signers of the message.
    public var signers: [CoseSignature] {
        get {
            return _signers
        }
        set {
            for signer in newValue {
                signer.parent = self
            }
            _signers = newValue
        }
    }
    private var _signers: [CoseSignature] = []
    
    // MARK: - Initialization
    public init(
        phdr: [CoseHeaderAttribute: Any]? = nil,
        uhdr: [CoseHeaderAttribute: Any]? = nil,
        payload: Data? = nil,
        signers: [CoseSignature] = []
    ) {
        super.init(phdr: phdr, uhdr: uhdr, payload: payload)
        self.signers = signers
    }
    
    // MARK: - Methods
    /// Decodes a COSE_Sign message from a CBOR object.
    /// - Parameters:
    ///   - coseObj: The CBOR object to decode.
    ///   - allowUnknownAttributes: Whether to allow unknown attributes.
    /// - Returns: The decoded SignMessage.
    public override class func fromCoseObject(coseObj: [CBOR]) throws -> CoseSignMessage {
        // Attempt to decode the base class message
        guard let msg = try super.fromCoseObject(coseObj: coseObj) as? CoseSignMessage else {
            throw CoseError.invalidMessage("Failed to decode base CoseSignMessage.")
        }

        var signers: [CoseSignature] = []
        
        // Pop the signature from the COSE object
        guard let signerArray = coseObj.first?.arrayValue  else {
            throw CoseError.invalidMessage("Missing or invalid signers.")
        }
        
        for signerCbor in signerArray {
            if let signerCborArray = signerCbor.arrayValue {
                signers.append(try CoseSignature.fromCoseObject(coseObj: signerCborArray))
            }
        }
        
        msg.signers = signers
        return msg
    }
    
    /// Encodes the message to CBOR.
    /// - Parameters:
    ///   - tag: Whether to include a CBOR tag.
    ///   - detachedPayload: An optional detached payload.
    /// - Returns: The encoded message as Data.
    public func encode(tag: Bool = true, detachedPayload: Data? = nil) throws -> Data {
        var cborMessage: [CBOR] = []
        cborMessage.append(phdrEncoded.toCBOR)
        cborMessage.append(CBOR.fromAny(uhdrEncoded))
        cborMessage.append(payload?.toCBOR ?? CBOR.null)
        
        if !signers.isEmpty {
            let encodedSigners = try signers.map {
                CBOR.array(try $0.encode(detachedPayload: detachedPayload))
            }
            cborMessage.append(CBOR.array(encodedSigners))
        }
        
        if tag {
            return try CBORSerialization.data(
                from: CBOR
                    .tagged(
                        CBOR.Tag(rawValue: UInt64(cborTag)),
                        CBOR.array(cborMessage)
                    )
            )
        } else {
            return try CBORSerialization.data(from: .array(cborMessage))
        }
    }
    
    // MARK: - Description
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let signersDescription = signers.map { $0.description }.joined(separator: ", ")
        return "<COSE_Sign: [\(phdr), \(uhdr), \(payloadDescription), [\(signersDescription)]]>"
    }
}


public class SignMessage: CoseSignMessage {
    // MARK: - Properties
    public override var context: String { "Signature" }
    public override var cborTag: Int { 98 }
}
