import Foundation
import CryptoKit

public class EC2Key: CoseKey {
    let curve: String
    var x: Data?
    var y: Data?
    var d: Data?
    var optionalParams: [String: Any]
    
    init(curve: String, x: Data? = nil, y: Data? = nil, d: Data? = nil, optionalParams: [String: Any] = [:]) throws {
        guard !curve.isEmpty else {
            throw CoseError.invalidKey("Curve cannot be empty")
        }
        self.curve = curve
        self.x = x
        self.y = y
        self.d = d
        self.optionalParams = optionalParams

        guard x != nil || d != nil else {
            throw CoseError.invalidKey("Either x or d must be present")
        }
    }

    static func fromDict(_ coseKey: [String: Any]) throws -> EC2Key {
        guard let curve = coseKey["EC2KpCurve"] as? String else {
            throw CoseError.invalidKey("Curve must be present")
        }
        let x = coseKey["EC2KpX"] as? Data
        let y = coseKey["EC2KpY"] as? Data
        let d = coseKey["EC2KpD"] as? Data
        var optionalParams = coseKey
        optionalParams.removeValue(forKey: "EC2KpCurve")
        optionalParams.removeValue(forKey: "EC2KpX")
        optionalParams.removeValue(forKey: "EC2KpY")
        optionalParams.removeValue(forKey: "EC2KpD")
        
        return try EC2Key(curve: curve, x: x, y: y, d: d, optionalParams: optionalParams)
    }
    
    static func generateKey(curve: String, optionalParams: [String: Any] = [:]) throws -> EC2Key {
        guard let cryptoCurve = getCryptoCurve(curve: curve) else {
            throw CoseError.unsupportedCurve("Curve \(curve) is not supported")
        }
        
        let privateKey = try cryptoCurve.generatePrivateKey()
        let publicKey = privateKey.publicKey
        let x = publicKey.x963Representation.subdata(in: 1..<1 + cryptoCurve.coordinateByteCount)
        let y = publicKey.x963Representation.subdata(in: 1 + cryptoCurve.coordinateByteCount..<1 + 2 * cryptoCurve.coordinateByteCount)
        
        return try EC2Key(curve: curve, x: x, y: y, d: privateKey.rawRepresentation, optionalParams: optionalParams)
    }
    
    static func getCryptoCurve(curve: String) -> P256.Signing.PrivateKey.Type? {
        switch curve {
        case "P-256":
            return P256.Signing.PrivateKey.self
        case "P-384":
            // Add support for P-384 curve with additional library
            return nil
        case "P-521":
            // Add support for P-521 curve with additional library
            return nil
        default:
            return nil
        }
    }
}

extension P256.Signing.PrivateKey {
    func publicKeyCoordinates() -> (x: Data, y: Data) {
        let x963 = self.publicKey.x963Representation
        let x = x963.subdata(in: 1..<33)
        let y = x963.subdata(in: 33..<65)
        return (x, y)
    }
}
