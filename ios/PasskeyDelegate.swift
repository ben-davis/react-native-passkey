import AuthenticationServices
import Foundation

@objc(PasskeyDelegate)
class PasskeyDelegate: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    private var _completion: (_ error: Error?, _ result: PassKeyResult?) -> Void

    // Initializes delegate with a completion handler (callback function)
    init(completionHandler: @escaping (_ error: Error?, _ result: PassKeyResult?) -> Void) {
        _completion = completionHandler
    }

    // Perform the authorization request for a given ASAuthorizationController instance
    @available(iOS 15.0, *)
    // @objc(performAuthForController:withPreferImmediatelyAvailableCredentials:)
    func
        performAuthForController(controller: ASAuthorizationController, preferImmediatelyAvailableCredentials: Bool)
    {
        controller.delegate = self
        controller.presentationContextProvider = self

        if #available(iOS 16.0, *), preferImmediatelyAvailableCredentials {
            controller.performRequests(options: .preferImmediatelyAvailableCredentials)
        } else {
            controller.performRequests()
        }
    }

    @available(iOS 16.0, *)
    func
        autofill(controller: ASAuthorizationController)
    {
        controller.delegate = self
        controller.presentationContextProvider = self

        controller.performAutoFillAssistedRequests()
    }

    @available(iOS 13.0, *)
    func presentationAnchor(for _: ASAuthorizationController) -> ASPresentationAnchor {
        return UIApplication.shared.keyWindow!
    }

    @available(iOS 13.0, *)
    func authorizationController(
        controller _: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        // Authorization request returned an error
        _completion(error, nil)
    }

    @available(iOS 13.0, *)
    func authorizationController(controller _: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        // Check if Passkeys are supported on this OS version
        if #available(iOS 15.0, *) {
            /** We need to determine whether the request was a registration or authentication request and if a security key was used or not */

            // Request was a registration request
            if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
                self.handlePlatformPublicKeyRegistrationResponse(credential: credential)
                // Request was an authentication request
            } else if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
                self.handlePlatformPublicKeyAssertionResponse(credential: credential)
                // Request was a registration request with security key
            } else if let credential = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialRegistration {
                self.handleSecurityKeyPublicKeyRegistrationResponse(credential: credential)
                // Request was an authentication request with security key
            } else if let credential = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialAssertion {
                self.handleSecurityKeyPublicKeyAssertionResponse(credential: credential)
            } else {
                self._completion(PassKeyError.requestFailed, nil)
            }
        } else {
            // Authorization credential was malformed, throw an error
            _completion(PassKeyError.notSupported, nil)
        }
    }

    @available(iOS 15.0, *)
    func handlePlatformPublicKeyRegistrationResponse(credential: ASAuthorizationPlatformPublicKeyCredentialRegistration) {
        if let rawAttestationObject = credential.rawAttestationObject {
            // Parse the authorization credential and resolve the callback
            let registrationResult = PassKeyRegistrationResult(credentialID: credential.credentialID,
                                                               rawAttestationObject: rawAttestationObject,
                                                               rawClientDataJSON: credential.rawClientDataJSON)
            _completion(nil, PassKeyResult(registrationResult: registrationResult))
        } else {
            // Authorization credential was malformed, throw an error
            _completion(PassKeyError.requestFailed, nil)
        }
    }

    @available(iOS 15.0, *)
    func handleSecurityKeyPublicKeyRegistrationResponse(credential: ASAuthorizationSecurityKeyPublicKeyCredentialRegistration) {
        if let rawAttestationObject = credential.rawAttestationObject {
            // Parse the authorization credential and resolve the callback
            let registrationResult = PassKeyRegistrationResult(credentialID: credential.credentialID,
                                                               rawAttestationObject: rawAttestationObject,
                                                               rawClientDataJSON: credential.rawClientDataJSON)
            _completion(nil, PassKeyResult(registrationResult: registrationResult))
        } else {
            // Authorization credential was malformed, throw an error
            _completion(PassKeyError.requestFailed, nil)
        }
    }

    @available(iOS 15.0, *)
    func handlePlatformPublicKeyAssertionResponse(credential: ASAuthorizationPlatformPublicKeyCredentialAssertion) {
        // Parse the authorization credential and resolve the callback
        let assertionResult = PassKeyAssertionResult(credentialID: credential.credentialID,
                                                     rawAuthenticatorData: credential.rawAuthenticatorData,
                                                     rawClientDataJSON: credential.rawClientDataJSON,
                                                     signature: credential.signature,
                                                     userID: credential.userID)
        _completion(nil, PassKeyResult(assertionResult: assertionResult))
    }

    @available(iOS 15.0, *)
    func handleSecurityKeyPublicKeyAssertionResponse(credential: ASAuthorizationSecurityKeyPublicKeyCredentialAssertion) {
        // Parse the authorization credential and resolve the callback
        let assertionResult = PassKeyAssertionResult(credentialID: credential.credentialID,
                                                     rawAuthenticatorData: credential.rawAuthenticatorData,
                                                     rawClientDataJSON: credential.rawClientDataJSON,
                                                     signature: credential.signature,
                                                     userID: credential.userID)
        _completion(nil, PassKeyResult(assertionResult: assertionResult))
    }
}
