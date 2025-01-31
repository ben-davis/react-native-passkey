import AuthenticationServices

@available(iOS 13.0, *)
@objc(Passkey)
class Passkey: NSObject {
    var passKeyDelegate: PasskeyDelegate?
    var authController: ASAuthorizationController?

    @objc(register:withChallenge:withDisplayName:withUserId:withSecurityKey:withPreferImmediatelyAvailableCredentials:withResolver:withRejecter:)
    func register(
        _ identifier: String,
        challenge: String,
        displayName: String,
        userId: String,
        securityKey: Bool,
        preferImmediatelyAvailableCredentials: Bool = false,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: @escaping RCTPromiseRejectBlock
    ) {
        // Convert challenge and userId to correct type
        guard let challengeData = Data(base64Encoded: challenge) else {
            reject(PassKeyError.invalidChallenge.rawValue, PassKeyError.invalidChallenge.rawValue, nil)
            return
        }
        let userIdData: Data = RCTConvert.nsData(userId)

        // Check if Passkeys are supported on this OS version
        if #available(iOS 15.0, *) {
            // If an existing controller is running, cancel it
            if #available(iOS 16.0, *) {
                if let authController {
                    authController.cancel()
                    self.authController = nil
                }
            }

            let authController: ASAuthorizationController

            // Check if registration should proceed with a security key
            if securityKey {
                // Create a new registration request with security key
                let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: identifier)
                let authRequest = securityKeyProvider.createCredentialRegistrationRequest(challenge: challengeData, displayName: displayName, name: displayName, userID: userIdData)
                authRequest.credentialParameters = [ASAuthorizationPublicKeyCredentialParameters(algorithm: ASCOSEAlgorithmIdentifier.ES256)]
                authController = ASAuthorizationController(authorizationRequests: [authRequest])
            } else {
                // Create a new registration request without security key
                let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: identifier)
                let authRequest = platformProvider.createCredentialRegistrationRequest(challenge: challengeData, name: displayName, userID: userIdData)
                authController = ASAuthorizationController(authorizationRequests: [authRequest])
            }

            // Set up a PasskeyDelegate instance with a callback function
            self.passKeyDelegate = PasskeyDelegate { error, result in
                // Check if authorization process returned an error and throw if thats the case
                if error != nil {
                    let passkeyError = self.handleErrorCode(error: error!)
                    reject(passkeyError.rawValue, passkeyError.rawValue, nil)
                    return
                }

                // Check if the result object contains a valid registration result
                if let registrationResult = result?.registrationResult {
                    // Return a NSDictionary instance with the received authorization data
                    let authResponse: NSDictionary = [
                        "rawAttestationObject": registrationResult.rawAttestationObject.base64EncodedString(),
                        "rawClientDataJSON": registrationResult.rawClientDataJSON.base64EncodedString(),
                    ]

                    let authResult: NSDictionary = [
                        "credentialID": registrationResult.credentialID.base64EncodedString(),
                        "response": authResponse,
                    ]
                    resolve(authResult)
                } else {
                    // If result didn't contain a valid registration result throw an error
                    reject(PassKeyError.requestFailed.rawValue, PassKeyError.requestFailed.rawValue, nil)
                }
            }

            if let passKeyDelegate = self.passKeyDelegate {
                // Perform the authorization request
                passKeyDelegate.performAuthForController(controller: authController, preferImmediatelyAvailableCredentials: preferImmediatelyAvailableCredentials)
            }
        } else {
            // If Passkeys are not supported throw an error
            reject(PassKeyError.notSupported.rawValue, PassKeyError.notSupported.rawValue, nil)
        }
    }

    @objc(authenticate:withChallenge:withCredentialIDs:withSecurityKey:withPreferImmediatelyAvailableCredentials:withResolver:withRejecter:)
    func authenticate(_ identifier: String, challenge: String, credentialIDs: [String], securityKey: Bool, preferImmediatelyAvailableCredentials: Bool = false, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
        // Convert challenge to correct type
        guard let challengeData = Data(base64Encoded: challenge) else {
            reject(PassKeyError.invalidChallenge.rawValue, PassKeyError.invalidChallenge.rawValue, nil)
            return
        }

        // Check if Passkeys are supported on this OS version
        if #available(iOS 15.0, *) {
            // If an existing controller is running, cancel it
            if #available(iOS 16.0, *) {
                if let authController {
                    authController.cancel()
                    self.authController = nil
                }
            }

            let authController: ASAuthorizationController

            // Check if authentication should proceed with a security key
            if securityKey {
                // Create a new assertion request with security key
                let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: identifier)
                let authRequest = securityKeyProvider.createCredentialAssertionRequest(challenge: challengeData)
                authController = ASAuthorizationController(authorizationRequests: [authRequest])
            } else {
                // Create a new assertion request without security key
                let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: identifier)
                let authRequest = platformProvider.createCredentialAssertionRequest(challenge: challengeData)

                if credentialIDs.isEmpty == false {
                    var ids: [ASAuthorizationPlatformPublicKeyCredentialDescriptor] = []

                    credentialIDs.forEach { base64Id in
                        guard let id = Data(base64Encoded: base64Id)
                        else { return }

                        ids.append(ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: id))
                    }

                    authRequest.allowedCredentials = ids
                }

                authController = ASAuthorizationController(authorizationRequests: [authRequest])
            }

            // Set up a PasskeyDelegate instance with a callback function
            self.passKeyDelegate = PasskeyDelegate { error, result in
                // Check if authorization process returned an error and throw if thats the case
                if error != nil {
                    let passkeyError = self.handleErrorCode(error: error!)
                    reject(passkeyError.rawValue, passkeyError.rawValue, nil)
                    return
                }
                // Check if the result object contains a valid authentication result
                if let assertionResult = result?.assertionResult {
                    // Return a NSDictionary instance with the received authorization data
                    let authResponse: NSDictionary = [
                        "rawAuthenticatorData": assertionResult.rawAuthenticatorData.base64EncodedString(),
                        "rawClientDataJSON": assertionResult.rawClientDataJSON.base64EncodedString(),
                        "signature": assertionResult.signature.base64EncodedString(),
                    ]

                    let authResult: NSDictionary = [
                        "credentialID": assertionResult.credentialID.base64EncodedString(),
                        "userID": String(decoding: assertionResult.userID, as: UTF8.self),
                        "response": authResponse,
                    ]
                    resolve(authResult)
                } else {
                    // If result didn't contain a valid authentication result throw an error
                    reject(PassKeyError.requestFailed.rawValue, PassKeyError.requestFailed.rawValue, nil)
                }
            }

            if let passKeyDelegate = self.passKeyDelegate {
                // Perform the authorization request
                passKeyDelegate.performAuthForController(controller: authController, preferImmediatelyAvailableCredentials: preferImmediatelyAvailableCredentials)
            }
        } else {
            // If Passkeys are not supported throw an error
            reject(PassKeyError.notSupported.rawValue, PassKeyError.notSupported.rawValue, nil)
        }
    }

    @objc(autofill:withChallenge:withSecurityKey:withResolver:withRejecter:)
    func autofill(_ identifier: String, challenge: String, securityKey: Bool, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
        // Convert challenge to correct type
        guard let challengeData = Data(base64Encoded: challenge) else {
            reject(PassKeyError.invalidChallenge.rawValue, PassKeyError.invalidChallenge.rawValue, nil)
            return
        }

        // Check if Passkeys are supported on this OS version
        if #available(iOS 16.0, *) {
            let authController: ASAuthorizationController

            // Check if authentication should proceed with a security key
            if securityKey {
                // Create a new assertion request with security key
                let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: identifier)
                let authRequest = securityKeyProvider.createCredentialAssertionRequest(challenge: challengeData)
                authController = ASAuthorizationController(authorizationRequests: [authRequest])
            } else {
                // Create a new assertion request without security key
                let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: identifier)
                let authRequest = platformProvider.createCredentialAssertionRequest(challenge: challengeData)
                authController = ASAuthorizationController(authorizationRequests: [authRequest])

                // Set the controller so we can cancel during an authentication
                self.authController = authController
            }

            // Set up a PasskeyDelegate instance with a callback function
            self.passKeyDelegate = PasskeyDelegate { error, result in
                // Check if authorization process returned an error and throw if thats the case
                if error != nil {
                    let passkeyError = self.handleErrorCode(error: error!)
                    reject(passkeyError.rawValue, passkeyError.rawValue, nil)
                    return
                }
                // Check if the result object contains a valid authentication result
                if let assertionResult = result?.assertionResult {
                    // Return a NSDictionary instance with the received authorization data
                    let authResponse: NSDictionary = [
                        "rawAuthenticatorData": assertionResult.rawAuthenticatorData.base64EncodedString(),
                        "rawClientDataJSON": assertionResult.rawClientDataJSON.base64EncodedString(),
                        "signature": assertionResult.signature.base64EncodedString(),
                    ]

                    let authResult: NSDictionary = [
                        "credentialID": assertionResult.credentialID.base64EncodedString(),
                        "userID": String(decoding: assertionResult.userID, as: UTF8.self),
                        "response": authResponse,
                    ]
                    resolve(authResult)
                } else {
                    // If result didn't contain a valid authentication result throw an error
                    reject(PassKeyError.requestFailed.rawValue, PassKeyError.requestFailed.rawValue, nil)
                }
            }

            if let passKeyDelegate = self.passKeyDelegate {
                // Perform the autofill request
                passKeyDelegate.autofill(controller: authController)
            }
        } else {
            // If Passkeys are not supported throw an error
            reject(PassKeyError.notSupported.rawValue, PassKeyError.notSupported.rawValue, nil)
        }
    }

    @objc(cancelAutofill:withRejecter:)
    func cancelAutofill(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
        // Check if Passkeys are supported on this OS version
        if #available(iOS 16.0, *) {
            if let authController {
                authController.cancel()
                self.authController = nil
            }
        }

        resolve(nil)
    }

    // Handles ASAuthorization error codes
    func handleErrorCode(error: Error) -> PassKeyError {
        let errorCode = (error as NSError).code
        switch errorCode {
        case 1001:
            return PassKeyError.cancelled
        case 1004:
            return PassKeyError.requestFailed
        case 4004:
            return PassKeyError.notConfigured
        default:
            return PassKeyError.unknown
        }
    }
}

enum PassKeyError: String, Error {
    case notSupported = "NotSupported"
    case requestFailed = "RequestFailed"
    case cancelled = "UserCancelled"
    case invalidChallenge = "InvalidChallenge"
    case notConfigured = "NotConfigured"
    case unknown = "UnknownError"
}

struct AuthRegistrationResult {
    var passkey: PassKeyRegistrationResult
    var type: PasskeyOperation
}

struct AuthAssertionResult {
    var passkey: PassKeyAssertionResult
    var type: PasskeyOperation
}

struct PassKeyResult {
    var registrationResult: PassKeyRegistrationResult?
    var assertionResult: PassKeyAssertionResult?
}

struct PassKeyRegistrationResult {
    var credentialID: Data
    var rawAttestationObject: Data
    var rawClientDataJSON: Data
}

struct PassKeyAssertionResult {
    var credentialID: Data
    var rawAuthenticatorData: Data
    var rawClientDataJSON: Data
    var signature: Data
    var userID: Data
}

enum PasskeyOperation {
    case Registration
    case Assertion
}
