import Foundation
import PotentCBOR

/// Parent class of all COSE message types.
public class CoseMessage: CoseBase {

    // MARK: - Static Properties
    /// Private dictionary to record all COSE message types dynamically
    private var coseMsgID: [UInt64: CoseMessage] = [:]

    // MARK: - Properties
    public var externalAAD: Data = Data()
    public var key: CoseKey?

    // MARK: - Abstract Methods
    public var cborTag: Int {
        fatalError("cborTag must be implemented in subclasses.")
    }

    // MARK: - Initialization
    public init(phdr: [String: CoseHeaderAttribute]? = nil,
                         uhdr: [String: CoseHeaderAttribute]? = nil,
                         payload: Data? = nil,
                         externalAAD: Data = Data(),
                         key: CoseKey? = nil) throws {
        try super.init(phdr: phdr, uhdr: uhdr)
        self.payload = payload
        self.externalAAD = externalAAD
        self.key = key
    }

    // MARK: - Class Methods
    /// Decorator to record all the CBOR tags dynamically.
    /// - Parameters:
    ///   - tag: The CBOR tag.
    ///   - messageType: The COSE message type.
    public func recordCBORTag(_ tag: UInt64, messageType: CoseMessage) {
        coseMsgID[tag] = messageType
    }
    
    /// Decode received COSE message based on the CBOR tag.
    /// If called on CoseMessage, this function can decode any supported
    /// message type. Otherwise, if called on a sub-class of CoseMessage,
    /// only messages of that type will be allowed to be decoded.
    ///
    /// - Parameters:
    ///   - type: The type of COSE message to decode.
    ///   - received: COSE messages encoded as bytes
    /// - Returns: The decoded COSE message.
    public class func decode<T: CoseMessage>(_ type: T.Type, from received: Data) throws -> T {
        let cborMessage = try CBORDecoder(input: received).decodeTag()
        guard let cborTag = cborMessage?.tag,
              let coseObj = cborMessage?.value as? [CBOR],
              let messageType = coseMsgID[cborTag] as? T.Type else {
            throw CoseError.invalidMessage("Unable to decode message.")
        }

        let message = try messageType.fromCoseObj(coseObj)
        return message
    }

    public class func fromCoseObj(_ coseObj: [CBOR]) throws -> Self {
        guard let payload = coseObj.first?.dataValue else {
            throw CoseError.invalidMessage("Invalid COSE object.")
        }

        let message = try self.init()
        message.payload = payload.toData
        return message
    }

    public func encode(message: [CBOR], tag: Bool = true) throws -> Data {
        if tag {
            return try CBORSerialization
                .data(
                    from: CBOR
                        .tagged(
                            CBOR.Tag(rawValue: self.cborTag),
                            CBOR.array(message)
                        )
                )
        } else {
            return try CBORSerialization.data(from: .array(message))
        }
    }

    public func baseStructure(_ structure: inout [CBOR]) {
        if ((phdr?.isEmpty) != nil) {
            structure.append(Data().toCBOR)
        } else {
            structure.append(phdrEncoded?.toCBOR ?? Data().toCBOR)
        }

        structure.append(externalAAD.toCBOR)
    }
}
