import Foundation
import PotentCBOR
import OrderedCollections

/// Basic COSE information buckets.
public class CoseBase {
    // MARK: - Properties
    public var payload: Data?
    public var algTstrEncoding: Bool = false

    /// The protected header, stored as a dictionary of attributes.
    private var _phdr: [AnyHashable: CoseHeaderAttribute] = [:]
    
    /// The encoded version of the protected header.
    private var _phdrEncoded: Data? = nil
    
    /// The unprotected header, stored as a dictionary of attributes.
    private var _uhdr: [AnyHashable: CoseHeaderAttribute] = [:]
    private var _localAttrs: [CoseHeaderAttribute: Any] = [:]
    
    // MARK: - Protected Header (phdr)
    public var phdr: [AnyHashable: CoseHeaderAttribute] {
        get {
            return _phdr
        }
        set {
            _phdr = newValue
            _phdrEncoded = nil // Reset encoded value
        }
    }
    
    // MARK: - Unprotected Header (uhdr)
    public var uhdr: [AnyHashable: CoseHeaderAttribute] {
        get {
            return _uhdr
        }
        set {
            _uhdr = newValue
        }
    }
    
    // MARK: - Local Attributes (localAttrs)
    public var localAttrs: [CoseHeaderAttribute: Any] {
        get {
            return _localAttrs
        }
        set {
            newValue.forEach { key, value in
                _localAttrs[key] = value
            }
        }
    }
    // MARK: - Encoded Protected Header (phdrEncoded)

    /// Encodes the protected header as CBOR.
    ///
    /// - Returns: The encoded protected header as `Data`.
    /// - Throws: An error if CBOR encoding fails.
    public var phdrEncoded: Data {
        get {
            if let encoded = _phdrEncoded {
                return encoded
            }
            
            guard phdr.isEmpty else { return Data() }

            do {
                // Convert `_phdr` to a CBOR.Map by mapping its keys and values
                let protectedHdrMap: OrderedDictionary<CBOR, CBOR> = OrderedDictionary(
                    uniqueKeysWithValues: try _phdr.compactMap {
                        if let key = $0.key as? Int {
                            return (CBOR.unsignedInt(UInt64(key)), CBOR.unsignedInt(UInt64($0.value.identifier)))
                        } else if let key = $0.key as? String {
                            return (CBOR.utf8String(key), CBOR.unsignedInt(UInt64($0.value.identifier)))
                        } else {
                            throw CoseError.valueError("Invalid key-value pair in `protected`: key=\($0.key), value=\($0.value)")
                        }
                    }
                )
                    
                let encoded = try CBORSerialization.data(from: .map(protectedHdrMap))
                _phdrEncoded = encoded
                return encoded
            } catch {
                fatalError("Failed to encode protected header: \(error)")
            }
        }
    }

    // MARK: - Encoded Unprotected Header (uhdrEncoded)

    /// Encodes the unprotected header.
    ///
    /// - Returns: The encoded unprotected header as a dictionary.
    public var uhdrEncoded: [AnyHashable: CoseHeaderAttribute] {
        return _uhdr
    }

    // MARK: - Helper Methods

    /// Updates the protected header with new attributes.
    /// Resets the encoded version to ensure consistency.
    ///
    /// - Parameter params: The attributes to add to the protected header.
    public func updateProtectedHeader(with params: [AnyHashable: CoseHeaderAttribute]) {
        params.forEach { _phdr[$0.key] = $0.value }
        _phdrEncoded = nil // Reset encoded value to trigger re-encoding.
    }

    /// Updates the unprotected header with new attributes.
    ///
    /// - Parameter params: The attributes to add to the unprotected header.
    public func updateUnprotectedHeader(with params: [AnyHashable: CoseHeaderAttribute]) {
        params.forEach { _uhdr[$0.key] = $0.value }
    }

    // MARK: - Initialization

    /// Initializes a new instance of the CoseBase class.
    ///
    /// - Parameters:
    ///   - phdr: The initial protected header (optional).
    ///   - uhdr: The initial unprotected header (optional).
    public init(phdr: [AnyHashable: CoseHeaderAttribute]? = nil, uhdr: [AnyHashable: CoseHeaderAttribute]? = nil) {
        if let phdr = phdr {
            self._phdr = phdr
        }
        if let uhdr = uhdr {
            self._uhdr = uhdr
        }
    }
    
    // MARK: - Initialization
    public init(phdr: [AnyHashable: CoseHeaderAttribute]? = nil, uhdr: [AnyHashable: CoseHeaderAttribute]? = nil, payload: Data? = nil, phdrEncoded: Data? = nil, algTstrEncoding: Bool? = false) throws {
        if phdr != nil && phdrEncoded != nil {
            throw CoseError.valueError("Cannot have both phdr and phdrEncoded")
        }
        
        if phdrEncoded != nil {
            if phdrEncoded!.isEmpty {
                self._phdr = [:]
            } else {
                let phdrCBOR = try CBORSerialization
                    .cbor(from: phdrEncoded!)
                if let map = phdrCBOR.mapValue {
                    map
                        .forEach {
                            (key, value) in self._phdr[key.utf8StringValue!] = (
                                value.unwrapped as! CoseHeaderAttribute
                            )
                        }
                }
            }
            
        } else if phdr == nil {
            self._phdr = [:]
        }

        self._uhdr = uhdr ?? [:]
        self.algTstrEncoding = algTstrEncoding ?? false
        
        self._phdrEncoded = phdrEncoded

        if let p = payload, !p.isEmpty {
            throw CoseError.valueError("Payload cannot be empty")
        }
        self.payload = payload
    }

    // MARK: - Methods
    public class func fromCoseObject(coseObj: inout [Any]) throws -> CoseBase {
        guard coseObj.count >= 2 else {
            throw CoseError.valueError("Insufficient elements in coseObj to construct a CoseBase")
        }
        
        let phdrEncoded = coseObj.removeFirst() as? Data
        let uhdr = coseObj.removeFirst() as? [String: CoseHeaderAttribute]

        return try CoseBase(
            uhdr: uhdr,
            phdrEncoded: phdrEncoded
        )
    }
    
    /// Fetches a header attribute from the COSE header buckets.
    /// - Parameters:
    ///   - attribute: A header parameter to fetch from the buckets.
    ///   - defaultResult: A default return value in case the attribute was not found.
    /// - Returns: If found returns a header attribute else 'None' or the default value.
    /// - Throws: `CoseError` When the same attribute is found in both the protected and unprotected header.
    public func getAttr(_ attribute: CoseHeaderAttribute, defaultResult: Any? = nil) throws -> Any? {
        let pAttr = phdr[attribute.fullname]
        let uAttr = uhdr[attribute.fullname]

        if let p = pAttr, let u = uAttr, p != u {
            throw CoseError.invalidHeader("MALFORMED: different values for the same header parameters in the header buckets")
        }

        return pAttr ?? uAttr ?? defaultResult
    }

    /// Updates the protected header with new attributes.
    /// Resets the encoded version to ensure consistency.
    ///
    /// - Parameter params: The attributes to add to the protected header.
    public func phdrUpdate(_ params: [AnyHashable: CoseHeaderAttribute]) {
        params.forEach { _phdr[$0.key] = $0.value }
        _phdrEncoded = nil
    }

    /// Updates the unprotected header with new attributes.
    ///
    /// - Parameter params: The attributes to add to the unprotected header.
    public func uhdrUpdate(_ params: [AnyHashable: CoseHeaderAttribute]) {
        params.forEach { _uhdr[$0.key] = $0.value }
    }

    // MARK: - Helper Methods
    private func parseHeader(_ header: [AnyHashable: Any], allowUnknownAttributes: Bool) throws -> [String: CoseHeaderAttribute?] {
        var decodedHeader: [String: CoseHeaderAttribute?] = [:]

        try header.forEach { key, value in
            let attribute = CoseHeaderAttribute.getInstance(
                for: CoseHeaderIdentifier(rawValue: key as! Int)!)
            
            decodedHeader[attribute.fullname] = try attribute.valueParser?(
                    value
            ) as? CoseHeaderAttribute ?? value as! CoseHeaderAttribute
        }

        return decodedHeader
    }
    
    public func hdrRepr() -> (phdr: [AnyHashable: Any], uhdr: [AnyHashable: Any]) {
        var phdr: [String: Any] = _phdr.reduce(into: [:]) { result, element in
            var keyName: String
            
            if let coseAttribute = element.key as? CoseAttribute {
                keyName = coseAttribute.fullname
            } else {
                keyName = "\(type(of: element.key))"
            }
            
            result[keyName] = "\(type(of: element.value))"
        }

        var uhdr: [String: Any] = _uhdr.reduce(into: [:]) { result, element in
            var keyName: String
            
            if let coseAttribute = element.key as? CoseAttribute {
                keyName = coseAttribute.fullname
            } else {
                keyName = "\(type(of: element.key))"
            }
            
            result[keyName] = "\(type(of: element.value))"
        }

        if let iv = phdr["IV"] as? String, !iv.isEmpty {
            phdr["IV"] = truncate(iv)
        }

        if let iv = uhdr["IV"] as? String, !iv.isEmpty {
            uhdr["IV"] = truncate(iv)
        }

        if let partialIv = phdr["PARTIAL_IV"] as? String, !partialIv.isEmpty {
            phdr["PARTIAL_IV"] = truncate(partialIv)
        }

        if let partialIv = uhdr["PARTIAL_IV"] as? String, !partialIv.isEmpty {
            uhdr["PARTIAL_IV"] = truncate(partialIv)
        }

        return (phdr, uhdr)
    }
}
