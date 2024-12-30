import Foundation
import PotentCBOR

public class CoseSignature: SignCommon {
    
    // MARK: - Properties
    public weak var parent: CoseSignMessage?
    
    public override var signature: Data? {
        get {
            return _payload
        }
        set {
            _payload = newValue
        }
    }
    private var _payload: Data?
    
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
    /// Parses COSE_Signature objects
    public override class func fromCoseObject(coseObj: [CBOR]) throws -> CoseSignature {
        guard let msg = try super.fromCoseObject(coseObj: coseObj) as? CoseSignature else {
            throw CoseError.invalidMessage("Failed to decode base CoseSignature.")
        }
        return msg
    }
    
    /// Creates the signature structure.
    /// - Parameter detachedPayload: An optional detached payload.
    /// - Returns: Encoded additional authenticated data (AAD).
    public override func createSignatureStructure(detachedPayload: Data? = nil) throws -> Data {
        guard let parent = parent else {
            throw CoseError.invalidMessage("Parent message is not set")
        }
        
        var signStructure: [CBOR] = [
            CBOR.utf8String(parent.context),
            parent.phdrEncoded.toCBOR
        ]
        
        if !phdrEncoded.isEmpty {
            signStructure.append(phdrEncoded.toCBOR)
        }
        
        signStructure.append(externalAAD.toCBOR)
        
        if detachedPayload == nil {
            guard let parentPayload = parent.payload else {
                throw CoseError.invalidMessage("Missing payload and no detached payload provided")
            }
            signStructure.append(parentPayload.toCBOR)
        } else {
            guard parent.payload == nil else {
                throw CoseError.invalidMessage("Detached payload must be None when payload is set")
            }
            signStructure.append(detachedPayload!.toCBOR)
        }
        
        return try CBORSerialization.data(from: .array(signStructure))
    }
    
    /// Encodes the COSE_Signature object.
    /// - Parameter detachedPayload: Optional detached payload.
    /// - Returns: Encoded CBOR representation of the signature.
    public func encode(detachedPayload: Data? = nil) throws -> [CBOR] {
        let computedSignature = try self.computeSignature(detachedPayload: detachedPayload)
        return [
            phdrEncoded.toCBOR,
            CBOR.fromAny(uhdrEncoded),
            computedSignature.toCBOR
        ]
    }
    
    // MARK: - Description
    public override var description: String {
        let (phdr, uhdr) = hdrRepr()
        let payloadDescription = truncate((payload?.base64EncodedString())!)
        
        return "<COSE_Signature: [phdr: \(phdr), uhdr: \(uhdr), payload: \(String(describing: payloadDescription))]>"
    }
}
