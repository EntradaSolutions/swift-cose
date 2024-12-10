import Foundation
import PotentCBOR

/// A COSE Sign1Message class, representing a COSE single signature message.
public class Sign1Message: CoseMessage {
    
    // MARK: - Properties
    public override var cborTag: Int {
        return 18 // CBOR tag for Sign1Message
    }
    
    private var signature: Data = Data()
    
    // MARK: - Initialization
    public required init(phdr: [String: CoseHeaderAttribute]? = nil,
                         uhdr: [String: CoseHeaderAttribute]? = nil,
                         payload: Data? = nil,
                         externalAAD: Data = Data(),
                         key: CoseKey? = nil) throws {
        try super.init(phdr: phdr, uhdr: uhdr, payload: payload, externalAAD: externalAAD, key: key)
    }
    
    // MARK: - Methods
    
    /// Decodes a COSE Sign1Message from a CBOR object.
    public override class func fromCoseObj(_ coseObj: [CBOR]) throws -> Self {
        guard coseObj.count == 4,
              let phdrEncoded = coseObj[0].dataValue,
              let uhdrEncoded = coseObj[1].dataValue,
              let payload = coseObj[2].dataValue,
              let signature = coseObj[3].dataValue else {
            throw CoseError.invalidMessage("Invalid COSE_Sign1 structure.")
        }
        
        let phdr = try CoseHeader.decode(phdrEncoded)
        let uhdr = try CoseHeader.decode(uhdrEncoded)
        
        let instance = try self.init(phdr: phdr, uhdr: uhdr, payload: payload)
        instance.signature = signature
        return instance
    }
    
    /// Encodes the Sign1Message as a CBOR structure with an optional tag.
    public override func encode(message: [CBOR], tag: Bool = true) throws -> Data {
        var cborMessage = [phdrEncoded?.toCBOR ?? Data().toCBOR,
                           uhdrEncoded?.toCBOR ?? Data().toCBOR,
                           payload?.toCBOR ?? Data().toCBOR,
                           signature.toCBOR]
        
        if tag {
            return try CBORSerialization.data(
                from: CBOR.tagged(CBOR.Tag(rawValue: cborTag), CBOR.array(cborMessage))
            )
        } else {
            return try CBORSerialization.data(from: .array(cborMessage))
        }
    }
    
    /// Computes the signature structure that needs to be signed.
    public func createSigStructure(detachedPayload: Data? = nil) throws -> Data {
        guard let context = "Signature1".data(using: .utf8) else {
            throw CoseError.invalidMessage("Invalid signature context.")
        }
        
        var sigStructure: [CBOR] = [context.toCBOR]
        baseStructure(&sigStructure)
        
        if let payload = detachedPayload ?? self.payload {
            sigStructure.append(payload.toCBOR)
        } else {
            throw CoseError.invalidMessage("Missing payload and no detached payload provided.")
        }
        
        return try CBORSerialization.data(from: .array(sigStructure))
    }
    
    // MARK: - Utility Methods
    public func setSignature(_ signature: Data) throws {
        guard !signature.isEmpty else {
            throw CoseError.invalidMessage("Signature must not be empty.")
        }
        self.signature = signature
    }
    
    public func getSignature() -> Data {
        return signature
    }
}
