import Foundation
import PotentCBOR

// MARK: - EncCommon

public class EncCommon: CoseMessage {
    // MARK: - Abstract Properties
    public override var cborTag: Int {
        fatalError("cborTag must be overridden in subclass.")
    }
    public var context: String {
        fatalError("Subclasses must implement the `context` property.")
    }

    public init(phdr: [String: CoseHeaderAttribute]? = nil,
                uhdr: [String: CoseHeaderAttribute]? = nil,
                payload: Data = Data(),
                externalAAD: Data = Data(),
                key: CoseSymmetricKey? = nil) throws {
        try super.init(
            phdr: phdr,
            uhdr: uhdr,
            payload: payload,
            externalAAD: externalAAD,
            key: key
        )
    }

    public func decrypt() throws -> Data {
        guard let key = self.key else {
            throw CoseError.invalidKey("Key cannot be nil")
        }

        guard let alg = getAlgorithm() else {
            throw CoseError.invalidAlgorithm("Algorithm not found in headers")
        }

        let nonce = try getNonce()
        try key.verifyKeyOperation(algorithm: alg, operations: [.decrypt])

        return try alg.decrypt(key: key, ciphertext: payload, aad: encStructure, nonce: nonce)
    }

    public func encrypt() throws -> Data {
        guard let key = self.key else {
            throw CoseError.invalidKey("Key cannot be nil")
        }

        guard let alg = getAlgorithm() else {
            throw CoseError.invalidAlgorithm("Algorithm not found in headers")
        }

        let nonce = try getNonce()
        try key.verifyKeyOperation(algorithm: alg, operations: [.encrypt])

        return try alg.encrypt(key: key, data: payload, aad: encStructure, nonce: nonce)
    }

    private var encStructure: Data {
        var structure: [Any] = [context]
        structure = baseStructure(structure)
        return try! CBOR.encode(structure)
    }

    private func baseStructure(_ structure: [Any]) -> [Any] {
        return structure + [phdr ?? [:], uhdr ?? [:], externalAAD]
    }

    private func getNonce() throws -> Data {
        if let iv = getHeader(.IV) as? Data {
            return iv
        }

        guard let baseIV = key?.baseIV, !baseIV.isEmpty else {
            throw CoseError.invalidIV("No IV found")
        }

        if let partialIV = getHeader(.PartialIV) as? Data {
            let nonceValue = partialIV.toInt() ^ baseIV.toInt()
            return nonceValue.toData()
        }

        throw CoseError.invalidIV("No IV found")
    }

    private func getAlgorithm() -> Algorithm? {
        return getHeader(.Algorithm) as? Algorithm
    }

    private func getHeader(_ header: Header) -> Any? {
        return phdr?[header.rawValue] ?? uhdr?[header.rawValue]
    }
}
