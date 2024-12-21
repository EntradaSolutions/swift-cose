import Foundation
import CryptoKit
import UncommonCrypto

public class EcdsaAlgorithm: CoseAlgorithm {
    // Sign the data
    public func sign(key: EC2Key, data: Data) throws -> Data? {
        fatalError("This method must be overridden in subclasses")
    }
    
    // Verify the signature
    public func verify(key: EC2Key, data: Data, signature: Data) throws -> Bool {
        fatalError("This method must be overridden in subclasses")
    }
}

public class Es256: EcdsaAlgorithm {
    public init() {
        super.init(identifier: .es256, fullname: "ES256")
    }
    
    // Sign the data
    public override func sign(key: EC2Key, data: Data) throws -> Data? {
        guard let privateKey = try? P256.Signing.PrivateKey(rawRepresentation: key.d) else {
            return nil
        }

        let signature = try privateKey.signature(for: data)
        return signature.derRepresentation
    }
    
    // Verify the signature
    public override func verify(key: EC2Key, data: Data, signature: Data) throws -> Bool {
        // Ensure the x and y data lengths match the curve requirements
        guard key.x.count == 32 && key.y.count == 32 else {
            throw CoseError.invalidKey("Invalid x or y length for P256 curve")
        }
        
        // Create x963Representation: a prefix of 0x04 followed by x and y concatenated
        var x963Representation = Data([0x04])
        x963Representation.append(key.x)
        x963Representation.append(key.y)
        
        guard let publicKey = try? P256.Signing.PublicKey(x963Representation: x963Representation) else {
            return false
        }
        
        do {
            let digest = SHA256.hash(data: data)
            return publicKey
                .isValidSignature(
                    try P256.Signing
                        .ECDSASignature(derRepresentation: signature),
                    for: digest
                )
        } catch {
            return false
        }
    }
}


public class Es384: EcdsaAlgorithm {
    public init() {
        super.init(identifier: .es384, fullname: "ES384")
    }
    
    // Sign the data
    public override func sign(key: EC2Key, data: Data) throws -> Data? {
        guard let privateKey = try? P384.Signing.PrivateKey(rawRepresentation: key.d) else {
            return nil
        }

        let signature = try privateKey.signature(for: data)
        return signature.derRepresentation
    }
    
    // Verify the signature
    public override func verify(key: EC2Key, data: Data, signature: Data) throws -> Bool {
        // Ensure the x and y data lengths match the curve requirements
        guard key.x.count == 32 && key.y.count == 32 else {
            throw CoseError.invalidKey("Invalid x or y length for P256 curve")
        }
        
        // Create x963Representation: a prefix of 0x04 followed by x and y concatenated
        var x963Representation = Data([0x04])
        x963Representation.append(key.x)
        x963Representation.append(key.y)
        
        guard let publicKey = try? P384.Signing.PublicKey(x963Representation: x963Representation) else {
            return false
        }
        
        do {
            let digest = SHA384.hash(data: data)
            return publicKey
                .isValidSignature(
                    try P384.Signing
                        .ECDSASignature(derRepresentation: signature),
                    for: digest
                )
        } catch {
            return false
        }
    }
}

public class Es512: EcdsaAlgorithm {
    public init() {
        super.init(identifier: .es512, fullname: "ES512")
    }
    
    // Sign the data
    public override func sign(key: EC2Key, data: Data) throws -> Data? {
        guard let privateKey = try? P521.Signing.PrivateKey(rawRepresentation: key.d) else {
            return nil
        }

        let signature = try privateKey.signature(for: data)
        return signature.derRepresentation
    }
    
    // Verify the signature
    public override func verify(key: EC2Key, data: Data, signature: Data) throws -> Bool {
        // Ensure the x and y data lengths match the curve requirements
        guard key.x.count == 32 && key.y.count == 32 else {
            throw CoseError.invalidKey("Invalid x or y length for P256 curve")
        }
        
        // Create x963Representation: a prefix of 0x04 followed by x and y concatenated
        var x963Representation = Data([0x04])
        x963Representation.append(key.x)
        x963Representation.append(key.y)
        
        guard let publicKey = try? P521.Signing.PublicKey(x963Representation: x963Representation) else {
            return false
        }
        
        do {
            let digest = SHA512.hash(data: data)
            return publicKey
                .isValidSignature(
                    try P521.Signing
                        .ECDSASignature(derRepresentation: signature),
                    for: digest
                )
        } catch {
            return false
        }
    }
}
