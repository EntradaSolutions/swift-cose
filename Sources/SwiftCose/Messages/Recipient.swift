import Foundation

/// Base class for all COSE Recipient types
public class CoseRecipient: CoseMessage {
    
    // Static dictionary to store recipient class mappings
    private static var recipientClasses: [CoseAlgorithm.Type: CoseRecipient.Type] = [:]
    
    // Recipients array
    public var recipients: [CoseRecipient] = []
    
    // Context for the recipient
    public var context: String = ""
    
    /// Register a recipient class for supported algorithms
    public static func registerRecipientClass(
        _ recipientClass: CoseRecipient.Type,
        for algorithms: [CoseAlgorithm.Type]
    ) {
        for algorithm in algorithms {
            recipientClasses[algorithm] = recipientClass
        }
    }
    
    /// Create a recipient instance based on the COSE object
    public static func createRecipient(from coseObj: [CBOR], allowUnknownAttributes: Bool, context: String) throws -> CoseRecipient {
        guard let phdr = coseObj.first?.dataValue,
              let uhdr = coseObj[safe: 1]?.dataValue else {
            throw CoseError.invalidMessage("Invalid COSE object structure for recipient.")
        }
        
        let pAlg = try parseHeader(phdr, allowUnknownAttributes).algorithm
        let uAlg = try parseHeader(uhdr, allowUnknownAttributes).algorithm
        
        if let algorithm = pAlg ?? uAlg,
           let recipientClass = recipientClasses[type(of: algorithm)] {
            let recipient = try recipientClass.init(fromCoseObj: coseObj)
            recipient.context = context
            return recipient
        } else {
            throw CoseError.invalidMessage("No algorithm specified in recipient structure.")
        }
    }
    
    // Initialization
    public required init(phdr: [String: CoseHeaderAttribute]? = nil,
                         uhdr: [String: CoseHeaderAttribute]? = nil,
                         payload: Data = Data(),
                         externalAAD: Data = Data(),
                         key: CoseKey? = nil,
                         recipients: [CoseRecipient] = []) {
        self.recipients = recipients
        super.init(phdr: phdr, uhdr: uhdr, payload: payload, externalAAD: externalAAD, key: key)
    }
    
    public required init(fromCoseObj coseObj: [CBOR]) throws {
        try super.init(phdr: nil, uhdr: nil, payload: Data(), externalAAD: Data(), key: nil)
        // Additional initialization logic for recipient
    }
    
    /// Abstract method to compute CEK
    public func computeCek(targetAlgorithm: CoseAlgorithm) throws -> Data {
        fatalError("This method must be implemented by subclasses.")
    }
    
    /// Encoding logic
    public func encode() throws -> [CBOR] {
        var encoded: [CBOR] = []
        encoded.append(phdrEncoded?.toCBOR ?? CBOR.null)
        encoded.append(uhdrEncoded?.toCBOR ?? CBOR.null)
        encoded.append(CBOR.byteString(payload))
        
        if !recipients.isEmpty {
            encoded.append(CBOR.array(try recipients.map { try $0.encode() }))
        }
        return encoded
    }
}
