import Foundation
import PotentCBOR

/// A COSE Sign1Message class, representing a COSE single signature message.
public class Sign1Message: SignCommon {
    // MARK: - Properties
    public var context: String { "Signature1" }
    public override var cborTag: Int { 18 }
    
    public override var signature: Data {
        get {
            return _signature
        }
        set {
            _signature = newValue
        }
    }
    private var _signature: Data = Data()
    
    // MARK: - Initialization
    public init(phdr: [CoseHeaderAttribute: Any]? = nil,
                uhdr: [CoseHeaderAttribute: Any]? = nil,
                payload: Data = Data(),
                externalAAD: Data = Data(),
                key: CoseSymmetricKey? = nil,
                recipients: [CoseRecipient] = []) {
        super.init(phdr: phdr,
                   uhdr: uhdr,
                   payload: payload,
                   externalAAD: externalAAD,
                   key: key)
    }
    
    // MARK: - Methods
    
    /// Decodes a COSE Sign1Message from a CBOR object.
    public override class func fromCoseObject(coseObj: inout [CBOR]) throws -> Sign1Message {
        guard let msg = try super.fromCoseObject(coseObj: &coseObj) as? Sign1Message else {
            throw CoseError.invalidMessage("Failed to decode base Sign1Message.")
        }
        
        // Pop the signature from the COSE object
        guard let signatureData = coseObj.first else {
            throw CoseError.invalidMessage("Missing or invalid signature.")
        }
        coseObj.removeFirst()
        msg.signature = signatureData.bytesStringValue!
            
        return msg
    }
    
    /// Encodes the Sign1Message as a CBOR structure with an optional tag.
    public func encode(tag: Bool = true, sign: Bool = true, detachedPayload: Data? = nil) throws -> Data {
        var cborMessage: [CBOR]
        
        if sign {
            let computedSignature = try self.computeSignature(detachedPayload: detachedPayload)
            cborMessage = [
                phdrEncoded.toCBOR,
                CBOR.fromAny(uhdrEncoded),
                payload?.toCBOR ?? Data().toCBOR,
                computedSignature.toCBOR
            ]
        } else if !signature.isEmpty {
            cborMessage = [
                phdrEncoded.toCBOR,
                CBOR.fromAny(uhdrEncoded),
                payload?.toCBOR ?? Data().toCBOR,
                signature.toCBOR
            ]
        } else {
            cborMessage = [
                phdrEncoded.toCBOR,
                CBOR.fromAny(uhdrEncoded),
                payload?.toCBOR ?? Data().toCBOR
            ]
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
    
    /// Computes the signature structure that needs to be signed.
    public override func createSignatureStructure(detachedPayload: Data? = nil) throws -> Data {
        var sigStructure: [CBOR] = [CBOR.utf8String(context)]
        baseStructure(&sigStructure)
        
        if detachedPayload == nil {
            guard let payload = self.payload else {
                throw CoseError
                    .valueError("Missing payload and no detached payload provided.")
            }
            sigStructure.append(payload.toCBOR)
        } else {
            guard self.payload != nil else {
                throw CoseError.valueError("Detached payload must be None when payload is set.")
            }
            sigStructure.append(detachedPayload!.toCBOR)
        }
        
        return try CBORSerialization.data(from: .array(sigStructure))
    }
    
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        let signatureDescription = truncate((signature.base64EncodedString()))
        return "<COSE_Sign1: [\(phdr), \(uhdr), \(payloadDescription), \(signatureDescription)]>"
    }
}
