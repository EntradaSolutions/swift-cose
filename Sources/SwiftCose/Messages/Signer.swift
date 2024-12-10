import Foundation
import PotentCBOR

public class CoseSignature: SignCommon {
    
    // MARK: - Properties
    public override var cborTag: Int {
        return -1 // No specific CBOR tag for CoseSignature
    }
    
    public var signature: Data {
        get { payload ?? Data() }
        set {
            guard !newValue.isEmpty else {
                fatalError("Signature must be non-empty")
            }
            payload = newValue
        }
    }
    
    private weak var parent: CoseMessage?
    
    // MARK: - Initialization
    public init(phdr: [String: CoseHeaderAttribute]? = nil,
                uhdr: [String: CoseHeaderAttribute]? = nil,
                signature: Data = Data(),
                externalAAD: Data = Data(),
                key: CoseKey? = nil,
                parent: CoseMessage? = nil) throws {
        try super.init(phdr: phdr, uhdr: uhdr, payload: signature, externalAAD: externalAAD, key: key)
        self.parent = parent
    }
    
    // MARK: - Methods
    /// Parses COSE_Signature objects
    public override class func fromCoseObj(_ coseObj: [CBOR]) throws -> Self {
        let instance = try super.fromCoseObj(coseObj)
        return instance
    }
    
    /// Creates the signature structure.
    /// - Parameter detachedPayload: An optional detached payload.
    /// - Returns: Encoded additional authenticated data (AAD).
    public func createSignatureStructure(detachedPayload: Data? = nil) throws -> Data {
        guard let parent = parent else {
            throw CoseError.invalidMessage("Parent message is not set")
        }
        
        var signStructure: [CBOR] = [parent.context.toCBOR, parent.phdrEncoded?.toCBOR ?? Data().toCBOR]
        
        if let phdrEncoded = phdrEncoded, !phdrEncoded.isEmpty {
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
        return [
            phdrEncoded?.toCBOR ?? Data().toCBOR,
            uhdrEncoded?.toCBOR ?? Data().toCBOR,
            try computeSignature(detachedPayload: detachedPayload).toCBOR
        ]
    }
    
    /// Computes the signature.
    /// - Parameter detachedPayload: An optional detached payload.
    /// - Returns: The computed signature as `Data`.
    private func computeSignature(detachedPayload: Data?) throws -> Data {
        let aad = try createSignatureStructure(detachedPayload: detachedPayload)
        // Compute signature logic here
        return Data() // Placeholder for actual signature computation
    }
    
    // MARK: - Description
    public override var description: String {
        return "<COSE_Signature: [\(phdrEncoded ?? Data()), \(uhdrEncoded ?? Data()), \(payload ?? Data())]>"
    }
}
