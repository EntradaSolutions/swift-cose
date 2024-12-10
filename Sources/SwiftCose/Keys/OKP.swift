import Foundation
import CryptoKit

public class OKPKey: CoseKey {
    public var curve: CoseCurve
    public var x: Data
    public var d: Data?
    public var optionalParams: [String: Any]
    public var allowUnknownKeyAttrs: Bool

    public init(curve: CoseCurve, x: Data, d: Data? = nil, optionalParams: [String: Any] = [:], allowUnknownKeyAttrs: Bool = true) throws {
        
        guard !x.isEmpty || d != nil else {
            throw CoseError.invalidKey("Public key cannot be empty")
        }

        self.curve = curve
        self.x = x
        self.d = d
        self.optionalParams = optionalParams
        self.allowUnknownKeyAttrs = allowUnknownKeyAttrs
    }

    public static func fromDict(_ coseKey: [String: Any]) throws -> OKPKey {
        guard let curve = coseKey["OKPKpCurve"] as? String,
              let x = coseKey["OKPKpX"] as? Data else {
            throw CoseError.invalidKey("Missing required key attributes")
        }
        let d = coseKey["OKPKpD"] as? Data
        var optionalParams = coseKey
        optionalParams.removeValue(forKey: "OKPKpCurve")
        optionalParams.removeValue(forKey: "OKPKpX")
        optionalParams.removeValue(forKey: "OKPKpD")

        return try OKPKey(curve: curve, x: x, d: d, optionalParams: optionalParams)
    }

    /// Generate a random OKPKey COSE key object.
    public static func generateKey(curve: CoseCurve, optionalParams: [String: Any] = [:]) throws -> OKPKey {
        let extKey = curve.curveObj.generateKeyPair()
        // Parse and validate the curve
        guard let crv = getSupportedCurve(curve) else {
            throw CoseError.unsupportedCurve("Unsupported curve: \(curve)")
        }

        let privateKey: any SigningKey
        let publicKey: Data

        // Key generation logic based on curve type
        switch crv {
        case "Ed25519":
            privateKey = Curve25519.Signing.PrivateKey()
            publicKey = privateKey.publicKey.rawRepresentation
        case "Ed448":
            // Ed448 is not natively supported in Swift; you'd need to use an external library like OpenSSL
            throw CoseError.unsupportedCurve("Unsupported curve: \(curve)")
        case "X25519":
            privateKey = Curve25519.KeyAgreement.PrivateKey()
            publicKey = privateKey.publicKey.rawRepresentation
        case "X448":
            // X448 is not natively supported in Swift; you'd need to use an external library like OpenSSL
            throw CoseError.unsupportedCurve("Unsupported curve: \(curve)")
        default:
            throw CoseError.unsupportedCurve("Unsupported curve: \(curve)")
        }

        // Prepare private bytes (d) and public bytes (x)
        let privateBytes = privateKey.rawRepresentation

        // Return the generated OKPKey
        return try OKPKey(curve: curve, x: publicKey, d: privateBytes, optionalParams: optionalParams)
    }

    public static func getSupportedCurve(_ curve: String) -> String? {
        let supportedCurves = ["Ed25519", "Ed448", "X25519", "X448"]
        return supportedCurves.contains(curve) ? curve : nil
    }
}
