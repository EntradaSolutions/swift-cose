import Foundation
import PotentCBOR

/// Basic COSE information buckets.
public class CoseBase {
    // MARK: - Properties
    public var phdrEncoded: Data?
    public var phdr: Dictionary<String, CoseHeaderAttribute>?
    public var uhdr: Dictionary<String, CoseHeaderAttribute>?
    public var payload: Data?
    public var localAttrs: Dictionary<String, CoseHeaderAttribute>? = [:]
    public var algTstrEncoding: Bool

    // MARK: - Initialization
    public init(phdr: [String: CoseHeaderAttribute]? = nil, uhdr: [String: CoseHeaderAttribute]? = nil, payload: Data? = nil, phdrEncoded: Data? = nil, algTstrEncoding: Bool? = false) throws {
        if phdr != nil && phdrEncoded != nil {
            throw CoseError.valueError("Cannot have both phdr and phdrEncoded")
        }
        
        if phdrEncoded != nil {
            if phdrEncoded!.isEmpty {
                self.phdr = [:]
            } else {
                let phdrCBOR = try CBORSerialization
                    .cbor(from: phdrEncoded!)
                if let map = phdrCBOR.mapValue {
                    map
                        .forEach {
                            (key, value) in self.phdr![key.utf8StringValue!] = (
                                value.unwrapped as! CoseHeaderAttribute
                            )
                        }
                }
            }
            
        } else if phdr == nil {
            self.phdr = [:]
        }

        self.uhdr = uhdr ?? [:]
        self.algTstrEncoding = algTstrEncoding ?? false
        
        self.phdrEncoded = phdrEncoded

        if let p = payload, !p.isEmpty {
            throw CoseError.valueError("Payload cannot be empty")
        }
        self.payload = payload
    }

    // MARK: - Methods
    public static func fromCoseObj(coseObj: inout [Any], allowUnknownAttributes: Bool) throws -> CoseBase {
        guard coseObj.count >= 2 else {
            throw CoseError.valueError("Insufficient elements in coseObj to construct a CoseBase")
        }
        
        let phdrEncoded = coseObj.removeFirst() as? Data
        let uhdr = coseObj.removeFirst() as? [String: CoseHeaderAttribute]

        return try CoseBase(
            phdr: nil,
            uhdr: uhdr,
            payload: nil,
            phdrEncoded: phdrEncoded
        )
    }
    
    /// Fetches a header attribute from the COSE header buckets.
    /// - Parameters:
    ///   - attribute: A header parameter to fetch from the buckets.
    ///   - default: A default return value in case the attribute was not found.
    /// - Returns: If found returns a header attribute else 'None' or the default value.
    /// - Throws: `CoseException` When the same attribute is found in both the protected and unprotected header.
    public func getAttr(_ attribute: CoseHeaderAttribute, default: Any? = nil) throws -> Any? {
        let pAttr = phdr?[attribute.fullname]
        let uAttr = uhdr?[attribute.fullname]

        if let p = pAttr, let u = uAttr, p != u {
            throw CoseError.invalidHeader("MALFORMED: different values for the same header parameters in the header buckets")
        }

        return pAttr ?? uAttr ?? `default`
    }

    public func phdrUpdate(_ params: [String: CoseHeaderAttribute]) {
        params.forEach { phdr![$0.key] = $0.value }
        phdrEncoded = nil
    }

    public func uhdrUpdate(_ params: [String: CoseHeaderAttribute]) {
        params.forEach { uhdr![$0.key] = $0.value }
    }

    public var phdrEncodedData: Data? {
        if let encoded = phdrEncoded {
            return encoded
        }
        guard phdr!.isEmpty else { return Data() }
        
        let cborData = try CBORSerialization.data(from: .map(phdr!.mapValues { $0.cborValue }))
        return cborData
    }

    public var uhdrEncodedData: [String: CoseHeaderAttribute] {
        return uhdr!
    }

    // MARK: - Helper Methods
    private func parseHeader(_ header: [AnyHashable: Any], allowUnknownAttributes: Bool) throws -> [String: CoseHeaderAttribute?] {
        var decodedHeader: [String: CoseHeaderAttribute?] = [:]

        try header.forEach { key, value in
            let attribute = CoseHeaderAttribute.getInstance(
                for: CoseHeaderIdentifier(rawValue: key as! Int)!)
            
                decodedHeader[attribute.fullname] = try attribute.valueParser?(
                    value
                ) as? CoseHeaderAttribute ?? value as? CoseHeaderAttribute
        }

        return decodedHeader
    }
}
