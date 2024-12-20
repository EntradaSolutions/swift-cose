import Foundation

/// Base class for all COSE Recipient types
public class CoseRecipient: CoseMessage {
    // Recipients array
    public var recipients: [CoseRecipient] = []
    
    // Context for the recipient
    public var context: String = ""
    
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
    public func computeCEK(targetAlgorithm: CoseAlgorithm, ops: String) throws -> CoseSymmetricKey {
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
    
    public func encode(targetAlg: CoseAlgorithm) throws -> Data {
        fatalError("This method must be implemented by subclasses.")
    }
    
    public static func verifyRecipients(_ recipients: [CoseRecipient]) throws -> Set<Any.Type> {
        var recipientTypes: Set<Any.Type> = []

        for recipient in recipients {
            recipientTypes.insert(type(of: recipient))
        }

        if recipientTypes.contains(DirectEncryption.self) && recipientTypes.count > 1 {
            throw CoseError.invalidRecipientConfiguration("When using DIRECT_ENCRYPTION mode, it must be the only mode used on the message.")
        }

        if recipientTypes.contains(DirectKeyAgreement.self) && recipients.count > 1 {
            throw CoseError.invalidRecipientConfiguration("When using DIRECT_KEY_AGREEMENT, it must be only one recipient in the message.")
        }

        return recipientTypes
    }
    
    /// Checks if a specific recipient is in the hierarchy of recipients.
    /// - Parameters:
    ///   - target: The `CoseRecipient` to search for.
    ///   - recipients: The list of `CoseRecipient` objects to search within.
    /// - Returns: A Boolean indicating whether the target recipient is found.
    public class func hasRecipient(target: CoseRecipient, in recipients: [CoseRecipient]) -> Bool {
        for recipient in recipients {
            if recipient === target { // Swift equivalent of Python's `is`
                return true
            } else if !recipient.recipients.isEmpty {
                if hasRecipient(target: target, in: recipient.recipients) {
                    return true
                }
            }
        }
        return false
    }
}
