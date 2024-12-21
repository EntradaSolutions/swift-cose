import Foundation
import PotentCodables
import PotentCBOR


/// Base class for all COSE Recipient types
public class CoseRecipient: CoseMessage {
    
    // MARK: - Properties
    // Context for the recipient
    public var context: String = ""
    
    // Recipients array
    public var recipients: [CoseRecipient] {
        get {
            return _recipients
        }
        set {
            for recipient in newValue {
                _recipients.append(recipient)
            }
        }
    }
    private var _recipients: [CoseRecipient] = []
    
    // MARK: - Abstract Methods
    public class func fromCoseObject(coseObj: inout [CBOR], context: String? = nil) throws -> CoseRecipient {
        fatalError("This method must be implemented by subclasses.")
    }
    
    /// Abstract method to compute CEK
    public func computeCEK(targetAlgorithm: EncAlgorithm, ops: String) throws -> CoseSymmetricKey? {
        fatalError("This method must be implemented by subclasses.")
    }
    
    /// Encoding logic
    public func encode(targetAlgorithm: CoseAlgorithm? = nil) throws -> [Any] {
        fatalError("This method must be implemented by subclasses.")
    }
    
    public func decrypt(targetAlgorithm: CoseAlgorithm) throws -> CoseKey {
        fatalError("This method must be implemented by subclasses.")
    }
    
    // MARK: - Initialization
    /// Create a COSE Recipient message.
    /// - Parameters:
    ///   - phdr: Protected header.
    ///   - uhdr: Unprotected header.
    ///   - payload: The payload of the COSE message.
    ///   - externalAAD: The external additional authenticated data.
    ///   - key: The symmetric key for encryption/decryption.
    ///   - recipients: The list of `CoseRecipient` objects.
    public required init(phdr: [CoseHeaderAttribute: Any]? = nil,
                         uhdr: [CoseHeaderAttribute: Any]? = nil,
                         payload: Data = Data(),
                         externalAAD: Data = Data(),
                         key: CoseSymmetricKey? = nil,
                         recipients: [CoseRecipient] = []) {
        super.init(phdr: phdr, uhdr: uhdr, payload: payload, externalAAD: externalAAD, key: key)
        self.recipients = recipients
    }
    
    // MARK: - Methods
    public class func fromAlgorithm(algorithm: CoseAlgorithm) -> CoseRecipient.Type? {
        let algorithmIdentifier = CoseAlgorithmIdentifier.fromFullName(algorithm.fullname)
        
        switch algorithmIdentifier {
            case .direct, .directHKDFAES256, .directHKDFSHA256:
                return DirectEncryption.self
            case .ecdhES_HKDF_256, .ecdhES_HKDF_512, .ecdhSS_HKDF_256, .ecdhSS_HKDF_512:
                return DirectKeyAgreement.self
            case .ecdhES_A128KW, .ecdhES_A192KW, .ecdhES_A256KW, .ecdhSS_A128KW, .ecdhSS_A192KW, .ecdhSS_A256KW:
                return KeyAgreementWithKeyWrap.self
            case .aesKW_128, .aesKW_192, .aesKW_256, .rsa_ES_OAEP_SHA1, .rsa_ES_OAEP_SHA256, .rsa_ES_OAEP_SHA512:
                return KeyWrap.self
            default:
                return nil
        }
    }
    
    /// Create a recipient instance based on the COSE object
    public class func createRecipient(recipient: CBOR.Array, context: String) throws -> CoseRecipient {
        // Check if the first item in the recipient array is not empty
        let pAlg: CoseAlgorithm?
        if let firstElement = recipient.first, !firstElement.isNull {
            let header = try parseHeader(hdr: firstElement.unwrapped as! [AnyHashable: Any])
            
            guard let alg = header[Algorithm()] as? CoseAlgorithm else {
                throw CoseError.invalidAlgorithm("Algorithm not found in protected headers")
            }
            
            pAlg = alg
        } else {
            pAlg = nil
        }

        // Parse the unprotected algorithm
        let uAlg: CoseAlgorithm? = try {
            let secondElement = recipient[1]
            if !secondElement.isNull {
                let header = try parseHeader(hdr: secondElement.unwrapped as! [AnyHashable: Any])
                
                guard let alg = header[Algorithm()] as? CoseAlgorithm else {
                    throw CoseError.invalidAlgorithm("Algorithm not found in unprotected headers")
                }
                return alg
            }
            return nil
        }()

        // Determine the appropriate recipient class based on the algorithms
        if pAlg != nil {
            let coseRecipientClass = fromAlgorithm(algorithm: pAlg!)
            var coseRecipient = recipient
            return try coseRecipientClass!
                .fromCoseObject(
                    coseObj: &coseRecipient,
                    context: context
                )
        } else if uAlg != nil {
            let coseRecipientClass = fromAlgorithm(algorithm: uAlg!)
            var coseRecipient = recipient
            return try coseRecipientClass!
                .fromCoseObject(
                    coseObj: &coseRecipient,
                    context: context
                )
        } else {
            throw CoseError.invalidMessage("No algorithm specified in recipient structure.")
        }
    }
    
    public static func verifyRecipients(_ recipients: [CoseRecipient]) throws -> Set<AnyHashable> {
        var recipientTypes: Set<AnyHashable> = []

        for recipient in recipients {
            recipientTypes.insert(String(describing: type(of: recipient)))
        }

        if recipientTypes.contains(String(describing: DirectEncryption.self)) && recipientTypes.count > 1 {
            throw CoseError.invalidRecipientConfiguration("When using DIRECT_ENCRYPTION mode, it must be the only mode used on the message.")
        }

        if recipientTypes.contains(String(describing: DirectKeyAgreement.self)) && recipients.count > 1 {
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
    
    /// Create a COSE KDF context for use by the key derivation algorithms.
    /// - Parameter algorithm: Specifies the target algorithm that will use the derived key.
    /// - Returns: A `CoseKDFContext` object.
    func getKDFContext(algorithm: EncAlgorithm) throws -> CoseKDFContext {
        
        // Extract PartyU information
        let uID = try getAttr(PartyUID()) as? Data
        let uNonce = try getAttr(PartyUNonce()) as? Data
        let uOther = try getAttr(PartyUOther()) as? Data
        let partyU = PartyInfo(identity: uID, nonce: uNonce, other: uOther)
        
        // Extract PartyV information
        let vID = try getAttr(PartyVID()) as? Data
        let vNonce = try getAttr(PartyVNonce()) as? Data
        let vOther = try getAttr(PartyVOther()) as? Data
        let partyV = PartyInfo(identity: vID, nonce: vNonce, other: vOther)
        
        // Create the SuppPubInfo
        let keyLength = algorithm.keyLength
        let suppPubOther = localAttrs[SuppPubOther()] as? Data ?? Data()
        let suppPub = SuppPubInfo(
            keyDataLength: keyLength!,
            protected: self.phdr,
            other: suppPubOther
        )
        
        // Get SuppPrivOther attribute
        let suppPriv = localAttrs[SuppPrivOther()] as? Data ?? Data()
        
        // Return the constructed KDF context
        return CoseKDFContext(
            algorithm: algorithm,
            suppPubInfo: suppPub,
            partyUInfo: partyU,
            partyVInfo: partyV,
            suppPrivInfo: suppPriv
        )
    }
    
    /// Sets up an ephemeral key and updates the unprotected header.
    /// - Parameters:
    ///   - peerKey: The peer's EC2 key.
    ///   - optionalParams: Optional parameters for key generation.
    /// - Throws: `CoseError` if an unrelated ephemeral key is already present.
    func setupEphemeralKey(peerKey: EC2Key, optionalParams: [AnyHashable: AnyValue] = [:]) throws {
        
        // Generate the ephemeral key using the curve from the peer key
        self.key = try EC2Key
            .generateKey(curve: peerKey.curve, optionalParams: optionalParams)
        
        // Check if the ephemeral key is already set in the headers
        if let _ = try? getAttr(EphemeralKey()) {
            throw CoseError.invalidMessage("Unrelated ephemeral public key found in COSE message header")
        } else {
            // Strip private components from the key to keep only the public part
            self.key!.store.removeValue(forKey: EC2KpD())  // Remove private key component
            
            // Update the unprotected header with the ephemeral public key
            uhdrUpdate([EphemeralKey(): self.key!.store])
        }
    }
}
