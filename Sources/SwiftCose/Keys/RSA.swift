import Foundation
import CryptoKit

public struct RSAKey {
    var n: Data = Data()
    var e: Data = Data()
    var d: Data = Data()
    var p: Data = Data()
    var q: Data = Data()
    var dp: Data = Data()
    var dq: Data = Data()
    var qInv: Data = Data()
    var other: [[String: Any]] = []
    var r_i: Data = Data()
    var d_i: Data = Data()
    var t_i: Data = Data()
    var optionalParams: [String: Any] = [:]
    var allowUnknownKeyAttrs: Bool = true

    init(n: Data = Data(), e: Data = Data(), d: Data = Data(), p: Data = Data(), q: Data = Data(), dp: Data = Data(), dq: Data = Data(), qInv: Data = Data(), other: [[String: Any]] = [], r_i: Data = Data(), d_i: Data = Data(), t_i: Data = Data(), optionalParams: [String: Any] = [:], allowUnknownKeyAttrs: Bool = true) throws {
        
        let isPublicKey = !n.isEmpty && !e.isEmpty && d.isEmpty && p.isEmpty && q.isEmpty && dp.isEmpty && dq.isEmpty && qInv.isEmpty && other.isEmpty && r_i.isEmpty && d_i.isEmpty && t_i.isEmpty

        let isPrivateKeyTwoPrimes = !n.isEmpty && !e.isEmpty && !d.isEmpty && !p.isEmpty && !q.isEmpty && !dp.isEmpty && !dq.isEmpty && !qInv.isEmpty && other.isEmpty && r_i.isEmpty && d_i.isEmpty && t_i.isEmpty

        let isPrivateKeyMultiplePrimes = !n.isEmpty && !e.isEmpty && !d.isEmpty && !p.isEmpty && !q.isEmpty && !dp.isEmpty && !dq.isEmpty && !qInv.isEmpty && !other.isEmpty && !r_i.isEmpty && !d_i.isEmpty && !t_i.isEmpty

        guard isPublicKey || isPrivateKeyTwoPrimes || isPrivateKeyMultiplePrimes else {
            throw CoseError.invalidKey("Invalid RSA key")
        }

        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dp = dp
        self.dq = dq
        self.qInv = qInv
        self.other = other
        self.r_i = r_i
        self.d_i = d_i
        self.t_i = t_i
        self.optionalParams = optionalParams
        self.allowUnknownKeyAttrs = allowUnknownKeyAttrs
    }

    static func generateKey(keyBits: Int) throws -> RSAKey {
        guard keyBits % 8 == 0 else {
            throw CoseError.invalidKey("Invalid key length")
        }

        let privateKey = try SecureEnclave.P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        return try RSAKey(
            n: publicKey.x963Representation,
            e: Data([0x01, 0x00, 0x01]),
            d: Data(),
            p: Data(),
            q: Data(),
            dp: Data(),
            dq: Data(),
            qInv: Data(),
            other: [],
            r_i: Data(),
            d_i: Data(),
            t_i: Data(),
            optionalParams: [:],
            allowUnknownKeyAttrs: true
        )
    }
    
    func supportsKeyType(key: Any) -> Bool {
        return key is SecureEnclave.P256.Signing.PrivateKey || key is SecureEnclave.P256.Signing.PublicKey
    }
}
