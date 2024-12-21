import Foundation
import CryptoKit
import CryptoSwift
import PotentCodables

public class RSAKey: CoseKey {
    var other: [[String: Any]] = []
    var r_i: Data?
    var d_i: Data?
    var t_i: Data?
    var optionalParams: [AnyHashable: Any] = [:]
    
    // MARK: - n Property
    var n: Data? {
        get {
            return store[RSAKpN()] as? Data
        }
        set {
            store[RSAKpN()] = newValue
        }
    }
    
    // MARK: - e Property
    var e: Data? {
        get {
            return store[RSAKpE()] as? Data
        }
        set {
            store[RSAKpE()] = newValue
        }
    }
    
    // MARK: - d Property
    var d: Data? {
        get {
            return store[RSAKpD()] as? Data
        }
        set {
            store[RSAKpD()] = newValue
        }
    }
    
    // MARK: - p Property
    var p: BigUInteger? {
        get {
            return store[RSAKpP()] as? BigUInteger
        }
        set {
            store[RSAKpP()] = newValue
        }
    }
    
    // MARK: - q Property
    var q: BigUInteger? {
        get {
            return store[RSAKpQ()] as? BigUInteger
        }
        set {
            store[RSAKpQ()] = newValue
        }
    }
    
    // MARK: - dp Property
    var dp: BigUInteger? {
        get {
            return store[RSAKpDP()] as? BigUInteger
        }
        set {
            store[RSAKpDP()] = newValue
        }
    }
    
    // MARK: - dq Property
    var dq: BigUInteger? {
        get {
            return store[RSAKpDQ()] as? BigUInteger
        }
        set {
            store[RSAKpDQ()] = newValue
        }
    }

    
    // MARK: - qInv Property
    var qInv: BigUInteger? {
        get {
            return store[RSAKpQInv()] as? BigUInteger
        }
        set {
            store[RSAKpQInv()] = newValue
        }
    }
    
    // MARK: - Key Operations
    private var _keyOps: [KeyOps] = []
    
    public override var keyOps: [KeyOps] {
        get {
            return _keyOps as [KeyOps]
        }
        set {
            let supportedOps: [KeyOps.Type] = [
                SignOp.self,
                VerifyOp.self,
                DeriveKeyOp.self,
                DeriveBitsOp.self
            ]
            
            for ops in newValue {
                // Check if the operation is supported by the key type
                guard supportedOps.contains(where: { $0 == type(of: ops) }) else {
                    fatalError("Invalid COSE key operation \(ops) for key type \(RSAKey.self)")
                }
            }
            _keyOps = newValue 
        }
    }
    
    // MARK: - Initialization Methods
    init(
        n: Data? = nil,
        e: Data? = nil,
        d: Data? = nil,
        p: BigUInteger? = nil,
        q: BigUInteger? = nil,
        dp: BigUInteger? = nil,
        dq: BigUInteger? = nil,
        qInv: BigUInteger? = nil,
        other: [[String: Any]] = [],
        r_i: Data? = nil,
        d_i: Data? = nil,
        t_i: Data? = nil,
        optionalParams: [AnyHashable: Any] = [:]
    ) throws {
        var transformedDict: [AnyHashable: Any] = [KpKty(): KtyRSA()]
        
        let isPublicKey = !n!.isEmpty && !e!.isEmpty && ((d?.isEmpty) != nil) && p == nil && q == nil && dp == nil && dq == nil && qInv == nil && other.isEmpty && ((r_i?.isEmpty) != nil) && ((d_i?.isEmpty) != nil) && (
            (t_i?.isEmpty) != nil
        )

        let isPrivateKeyTwoPrimes = !n!.isEmpty && !e!.isEmpty && !d!.isEmpty && p != nil && q != nil && dp != nil && dq != nil && qInv != nil && other.isEmpty && r_i!.isEmpty && d_i!.isEmpty && t_i!.isEmpty

        let isPrivateKeyMultiplePrimes = !n!.isEmpty && !e!.isEmpty && !d!.isEmpty && p != nil && q != nil && dp != nil && dq != nil && qInv != nil && !other.isEmpty && !r_i!.isEmpty && !d_i!.isEmpty && !t_i!.isEmpty

        guard isPublicKey || isPrivateKeyTwoPrimes || isPrivateKeyMultiplePrimes else {
            throw CoseError.invalidKey("Invalid RSA key")
        }
        
        // Validate key type
        guard transformedDict[KpKty()] as! CoseAttribute == KtyRSA() else {
            throw CoseError.invalidKey("Illegal key type in RSA COSE Key: \(String(describing: transformedDict[KpKty()]))")
        }
        
        // Transform optional parameters
        for (key, value) in optionalParams {
            let kp = try RSAKeyParam.fromId(for: key)
            if let parser = kp.valueParser {
                transformedDict[kp] = try parser(value)
            } else {
                transformedDict[kp] = value
            }
        }
        
        self.optionalParams = transformedDict
        
        super.init(keyDict: transformedDict)

        self.n = n
        self.e = e
        self.d = d
        self.p = p ?? 0
        self.q = q ?? 0
        self.dp = dp ?? 0
        self.dq = dq ?? 0
        self.qInv = qInv ?? 0
        self.other = other
        self.r_i = r_i
        self.d_i = d_i
        self.t_i = t_i
        self.optionalParams = optionalParams
    }
    
    // MARK: - Methods
    
    /// Returns an initialized COSE Key object of type `RSAKey`.
    /// - Parameters:
    ///   - extKey: The external RSA key object.
    ///   - optionalParams: The optional parameters.
    /// - Returns: An initialized `RSAkey`
    public static func fromCryptographyKey(extKey: Any, optionalParams: [AnyHashable: AnyValue]) throws -> RSAKey {
        guard RSAKey.supportsCryptographyKeyType(extKey) else {
            throw CoseError.invalidKey("Unsupported key type: \(type(of: extKey))")
        }
        
        var n: BigUInteger?
        var e: BigUInteger?
        var d: BigUInteger?
        
        
        if let privateKey = extKey as? RSA {
            n = privateKey.n
            e = privateKey.e
            d = privateKey.d
        }
        
        var coseKey: [AnyHashable : AnyValue] = [
            RSAKpE(): toBstr(e!),
            RSAKpN(): toBstr(n!),
        ] as! [AnyHashable : AnyValue]
        
        if let d = d { coseKey[RSAKpD()] = AnyValue.data(toBstr(d)) }
        
        return try RSAKey(
            n: n!.toData,
            e: e!.toData,
            d: d?.toData ?? Data(),
            optionalParams: optionalParams
        )
    }
    
    /// Generate a random RSAKey COSE key object. The RSA keys have two primes (see section 4 of RFC 8230).
    /// - Parameters:
    ///  - keyBits: The key length in bits.
    ///  - optionalParams: The optional parameters.
    /// - Returns: A COSE `RSAKey` key.
    static func generateKey(keyBits: Int, optionalParams: [AnyHashable: AnyValue] = [:]) throws -> RSAKey {
        guard keyBits % 8 == 0 else {
            throw CoseError.invalidKey("Invalid key length")
        }
        
        // Generate prime numbers
        let p = BigUInteger.generatePrime(keyBits / 2)
        let q = BigUInteger.generatePrime(keyBits / 2)
        
        // Calculate modulus
        let n = p * q

        // Calculate public and private exponent
        let e: BigUInteger = 65537
        let phi = (p - 1) * (q - 1)
        guard let d = e.inverse(phi) else {
          throw RSA.Error.invalidInverseNotCoprimes
        }

        let extKey = try RSA(n: n, e: e, d: d, p: p, q: q)
        
        var additionalParams: [AnyHashable : AnyValue] = [
            RSAKpP():toBstr(p),
            RSAKpQ():toBstr(q),
        ] as! [AnyHashable : AnyValue]
        
        // Merge optional params
        for (key, value) in optionalParams {
            additionalParams[key] = value
        }

        return try RSAKey.fromCryptographyKey(extKey: extKey, optionalParams: additionalParams)
    }
    
    /// Returns an initialized COSE Key object of type RSAKey.
    /// - Parameter coseKey: Dict containing COSE Key parameters and there values.
    /// - Returns: An initialized RSAKey key.
    public override static func fromDictionary(_ coseKey: [AnyHashable: Any]) throws -> RSAKey {
        let e = CoseKey.extractFromDict(coseKey, parameter: RSAKpE())
        let n = CoseKey.extractFromDict(coseKey, parameter: RSAKpN())
        let d = CoseKey.extractFromDict(coseKey, parameter: RSAKpD())
        let p = CoseKey.extractFromDict(coseKey, parameter: RSAKpP())
        let q = CoseKey.extractFromDict(coseKey, parameter: RSAKpQ())
        let dp = CoseKey.extractFromDict(coseKey, parameter: RSAKpDP())
        let dq = CoseKey.extractFromDict(coseKey, parameter: RSAKpDQ())
        let qInv = CoseKey.extractFromDict(coseKey, parameter: RSAKpQInv())
        let other = CoseKey.extractFromDict(
            coseKey,
            parameter: RSAKpOther(),
            defaultValue: []
        )
        let r_i = CoseKey.extractFromDict(coseKey, parameter: RSAKpRi())
        let d_i = CoseKey.extractFromDict(coseKey, parameter: RSAKpDi())
        let t_i = CoseKey.extractFromDict(coseKey, parameter: RSAKpTi())
        
        var optionalParams: [AnyHashable : Any] = coseKey
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpE())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpN())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpD())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpP())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpQ())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpDP())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpDQ())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpQInv())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpOther())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpRi())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpDi())
        CoseKey.removeFromDict(&optionalParams, parameter: RSAKpTi())
        
        return try RSAKey(
            n: n as? Data,
            e: e as? Data,
            d: d as? Data,
            p: p as? BigUInteger,
            q: q as? BigUInteger,
            dp: dp as? BigUInteger,
            dq: dq as? BigUInteger,
            qInv: qInv as? BigUInteger,
            other: other as! [[String: Any]],
            r_i: r_i as? Data,
            d_i: d_i as? Data,
            t_i: t_i as? Data,
            optionalParams: optionalParams as! [String : Any]
        )
    }
    
    // MARK: - Helpers
    
    public static func supportsCryptographyKeyType(_ key: Any) -> Bool {
        let supportedKeyTypes: [Any] = [
            RSA.PrivateKey.self,
            RSA.PublicKey.self,
        ]
        
        return supportedKeyTypes.contains(where: { $0 as? any Any.Type == type(of: key) })
    }
    
    // Custom description for the object
    public override var description: String {
        let keyRepresentation = keyRepr()

        return "<COSE_Key(RSAKey): \(keyRepresentation)>"
    }
}
