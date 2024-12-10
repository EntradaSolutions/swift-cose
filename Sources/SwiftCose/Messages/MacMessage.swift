import Foundation
import PotentCBOR

/// COSE MACed Message with Recipients
public class MacMessage: MacCommon {
    
    // MARK: - Properties
    public var tag: Data = Data()
    public var recipients: [CoseRecipient] = []
    
    public override var cborTag: Int {
        return 97
    }
    
    // MARK: - Initialization
    public init(phdr: [String: CoseHeaderAttribute]? = nil,
                uhdr: [String: CoseHeaderAttribute]? = nil,
                payload: Data? = nil,
                externalAAD: Data = Data(),
                key: CoseKey? = nil,
                recipients: [CoseRecipient] = []) throws {
        try super.init(phdr: phdr, uhdr: uhdr, payload: payload, externalAAD: externalAAD, key: key)
        self.recipients = recipients
    }
    
    // MARK: - Methods
    public override class func fromCoseObj(_ coseObj: [CBOR]) throws -> Self {
        guard coseObj.count >= 4 else {
            throw CoseError.invalidMessage("COSE MAC object is incomplete.")
        }
        
        let phdr = try CoseHeader.decode(from: coseObj[0].dataValue)
        let uhdr = try CoseHeader.decode(from: coseObj[1].dataValue)
        let payload = coseObj[2].dataValue
        let tag = coseObj[3].dataValue
        
        let recipients: [CoseRecipient] = try coseObj[safe: 4]?.arrayValue?.compactMap {
            try CoseRecipient.fromCbor($0)
        } ?? []
        
        let message = try self.init(phdr: phdr, uhdr: uhdr, payload: payload, externalAAD: Data())
        message.tag = tag
        message.recipients = recipients
        return message
    }
    
    public func encode(tag: Bool = true, mac: Bool = true) throws -> Data {
        var message: [CBOR] = [
            phdrEncoded?.toCBOR ?? CBOR.null,
            uhdrEncoded?.toCBOR ?? CBOR.null,
            payload?.toCBOR ?? CBOR.null
        ]
        
        if mac {
            message.append(CBOR.data(self.computeTag()))
        }
        
        if !recipients.isEmpty {
            let encodedRecipients = try recipients.map { try $0.encode() }
            message.append(CBOR.array(encodedRecipients))
        }
        
        return try super.encode(message: message, tag: tag)
    }
    
    public func computeTag() -> Data {
        // Replace with your tag computation logic.
        return Data() // Placeholder for actual tag computation.
    }
    
    public override var description: String {
        let phdrDesc = phdrEncoded?.description ?? "nil"
        let uhdrDesc = uhdrEncoded?.description ?? "nil"
        let payloadDesc = payload?.base64EncodedString() ?? "nil"
        let tagDesc = tag.base64EncodedString()
        let recipientsDesc = recipients.map { $0.description }.joined(separator: ", ")
        return "<COSE_Mac: [\(phdrDesc), \(uhdrDesc), \(payloadDesc), \(tagDesc), [\(recipientsDesc)]]>"
    }
}
