import Foundation
import PotentCBOR

public enum CoseMessageIdentifier: Int, Codable, Equatable {
    case encrypt0 = 16
    case encrypt = 96
    case mac0 = 17
    case mac = 97
    case sign1 = 18
    case sign = 98
    
    /// Returns the appropriate `CoseMessageIdentifier` for the given fullname.
    /// - Parameter fullname: The string fullname of the algorithm.
    /// - Returns: The corresponding `CoseMessageIdentifier` if found, otherwise nil.
    public static func fromFullName(_ fullName: String) -> CoseMessageIdentifier? {
        switch fullName {
            case "COSE_Encrypt0":
                return .encrypt0
            case "COSE_Encrypt":
                return .encrypt
            case "COSE_Mac0":
                return .mac0
            case "COSE_Mac":
                return .mac
            case "COSE_Sign1":
                return .sign1
            case "COSE_Sign":
                return .sign
            default:
                return nil
        }
    }
}

/// Parent class of all COSE message types.
public class CoseMessage: CoseBase, CustomStringConvertible {
    
    public var description: String {
        fatalError("Must be overridden in subclass.")
    }
    
    // MARK: - Properties
    /// External Additional Authenticated Data (AAD).
    private var _externalAAD: Data = Data()

    /// Key associated with the COSE message.
    private var _key: CoseKey?

    /// Payload of the COSE message, which can be plaintext or ciphertext.
    private var _payload: Data?
    
    /// External Additional Authenticated Data (AAD).
    public var externalAAD: Data {
        get {
            return _externalAAD
        }
        set {
            guard type(of: newValue) == Data.self else {
                fatalError("externalAAD must be of type `Data`")
            }
            _externalAAD = newValue
        }
    }

    /// The key associated with the COSE message.
    public var key: CoseKey? {
        get {
            return _key
        }
        set {
            if let newKey = newValue {
                guard newKey is CoseSymmetricKey || newKey is EC2Key || newKey is OKPKey || newKey is RSAKey else {
                    fatalError("Unknown key type: \(type(of: newKey))")
                }
            }
            _key = newValue
        }
    }

    /// The payload of the COSE message.
    public override var payload: Data? {
        get {
            return _payload
        }
        set {
            guard newValue == nil || type(of: newValue!) == Data.self else {
                fatalError("payload must be of type `Data` or `nil`, not \(type(of: newValue!))")
            }
            _payload = newValue
        }
    }

    // MARK: - Abstract Methods
    public var cborTag: Int {
        fatalError("cborTag must be implemented in subclasses.")
    }

    // MARK: - Initialization

    /// Initializes a new instance of the CoseMessage class.
    ///
    /// - Parameters:
    ///   - phdr: Protected header dictionary (optional).
    ///   - uhdr: Unprotected header dictionary (optional).
    ///   - payload: The payload of the COSE message (optional).
    ///   - externalAAD: External AAD for the COSE message (default: empty data).
    ///   - key: Key associated with the COSE message (optional).
    public init(phdr: [AnyHashable: CoseHeaderAttribute]? = nil,
                uhdr: [AnyHashable: CoseHeaderAttribute]? = nil,
                payload: Data? = nil,
                externalAAD: Data = Data(),
                key: CoseSymmetricKey? = nil) {
        super.init(phdr: phdr, uhdr: uhdr)
        self.payload = payload
        self.externalAAD = externalAAD
        self.key = key
    }

    
    // MARK: - Methods
    public static func fromId(for attribute: Any) throws -> CoseMessage.Type {
        switch attribute {
            case let id as Int:
                // If the identifier is an Int, convert it to CoseMessageIdentifier
                guard let messageId = CoseMessageIdentifier(rawValue: id) else {
                    throw CoseError.invalidMessage("Unknown identifier")
                }
                return getInstance(for: messageId)
                
            case let name as String:
                // If the identifier is a String, attempt to match it to a CoseMessageIdentifier
                guard let messageId = CoseMessageIdentifier.fromFullName(name) else {
                    throw CoseError.invalidMessage("Unknown fullname")
                }
                return getInstance(for: messageId)
                
            case let messageId as CoseMessageIdentifier:
                // If the identifier is already a CoseMessageIdentifier, get the instance directly
                return getInstance(for: messageId)
                
            default:
                throw CoseError.invalidMessage("Unsupported identifier type. Must be Int, String, or CoseMessageIdentifier")
        }
    }
    
    public class func getInstance(for identifier: CoseMessageIdentifier) -> CoseMessage.Type {
        switch identifier {
            case .encrypt0:
                return Enc0Message.self
            case .encrypt:
                return EncMessage.self
            case .mac0:
                return Mac0Message.self
            case .mac:
                return MacMessage.self
            case .sign1:
                return Sign1Message.self
            case .sign:
                return  SignMessage.self
        }
    }
    
    /// Function to return an initialized COSE message object.
    /// - Parameter coseObj: The CBOR object to decode.
    /// - Returns: The decoded COSE message.
    public override class func fromCoseObject(coseObj: inout [Any]) throws -> CoseMessage {
        let msg = try super.fromCoseObject(coseObj: &coseObj) as! CoseMessage
        msg.payload = coseObj.removeLast() as? Data
        return msg
    }
    
    /// Decode received COSE message based on the CBOR tag.
    ///
    /// If called on CoseMessage, this function can decode any supported
    /// message type. Otherwise, if called on a sub-class of CoseMessage,
    /// only messages of that type will be allowed to be decoded.
    ///
    /// - Parameters:
    ///   - type: The type of COSE message to decode.
    ///   - received: COSE messages encoded as bytes
    /// - Returns: The decoded COSE message.
    public class func decode<T: CoseMessage>(_ type: T.Type, from received: Data) throws -> T {
        let cborMsg = try CBORSerialization.cbor(from: received)
        let cborTag = cborMsg.tag
        let cborObj = cborMsg.value
        
        if cborTag == nil {
            throw CoseError.attributeError("Message is not tagged.")
        }
        if cborObj == nil {
            throw CoseError.valueError("Decode accepts only bytes as input.")
        }
        
        if var messageType = cborObj?.unwrapped as? [Any] {
            do {
                let decoded = try T.fromCoseObject(
                    coseObj: &messageType
                )
                return decoded as! T
            } catch {
                throw CoseError.invalidMessage("Unable to decode message.")
            }
        } else {
            throw CoseError.invalidMessage("Invalid message structure.")
        }
    }

    public func encode(message: [CBOR], tag: Bool = true) throws -> Data {
        if tag {
            return try CBORSerialization
                .data(
                    from: CBOR
                        .tagged(
                            CBOR.Tag(rawValue: UInt64(self.cborTag)),
                            CBOR.array(message)
                        )
                )
        } else {
            return try CBORSerialization.data(from: .array(message))
        }
    }

    public func baseStructure(_ structure: inout [CBOR]) {
        if phdr.isEmpty {
            structure.append(Data().toCBOR)
        } else {
            structure.append(phdrEncoded.toCBOR)
        }

        structure.append(externalAAD.toCBOR)
    }
}
