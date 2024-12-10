import Foundation
import OrderedCollections
import PotentCBOR

public class Enc0Message: EncCommon {
    public override var context: String { "Encrypt0" }
    public override var cborTag: Int { 16 }

    // MARK: - Static Properties
    private static var coseMsgId: [Int: CoseMessage] = [:]


    // MARK: - Initialization
    public init(phdr: [String: Any] = [:],
                uhdr: [String: Any] = [:],
                payload: Data? = nil,
                externalAad: Data = Data(),
                key: CoseKey? = nil) {
        self.phdr = phdr
        self.uhdr = uhdr
        self.payload = payload
        self.externalAad = externalAad
        self.key = key
    }

    // MARK: - Static Methods
    public class func recordCborTag(_ cborTag: Int, messageType: CoseMessage) {
        coseMsgId[cborTag] = messageType
    }

    public class func decode(_ received: Data) throws -> CoseMessage {
        do {
            let cborMsg = try CBORSerialization.cbor(from: received)
            guard let taggedCbor = cborMsg.taggedValue else {
                throw CoseError.invalidTag("Message was not tagged.")
            }

            guard let coseObj = taggedCbor.value.arrayValue else {
                throw CoseError.invalidStructure("Expected CBOR array structure.")
            }

            guard let messageType = coseMsgId[taggedCbor.tag] else {
                throw CoseError.unrecognizedTag("Unrecognized CBOR tag: \(taggedCbor.tag)")
            }

            let message = try messageType.fromCborObject(coseObj)
            return message
        } catch {
            throw error
        }
    }

    public class func fromCborObject(_ cborObject: [CBOR]) throws -> CoseMessage {
        let phdr = cborObject[0].dictionaryValue ?? [:]
        let uhdr = cborObject[1].dictionaryValue ?? [:]
        let payload = cborObject[2].dataValue

        return CoseMessage(phdr: phdr, uhdr: uhdr, payload: payload)
    }

    // MARK: - Encoding
    public func encode(tag: Bool = true) throws -> Data {
        var message: [CBOR] = []

        if phdr.isEmpty {
            message.append(CBOR.byteString(Data()))
        } else {
            message.append(CBOR.map(phdr.mapKeysToCbor()))
        }

        if uhdr.isEmpty {
            message.append(CBOR.byteString(Data()))
        } else {
            message.append(CBOR.map(uhdr.mapKeysToCbor()))
        }

        message.append(payload != nil ? CBOR.byteString(payload!) : CBOR.null)

        if tag {
            return try CBORSerialization.data(from: .taggedValue(CBOR.Tag(tag: cborTag, value: .array(message))))
        } else {
            return try CBORSerialization.data(from: .array(message))
        }
    }
}
