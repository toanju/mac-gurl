# encoding: utf-8
#
# Copyright 2009-2025 Greg Neagle.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
gurl.py

Created by Greg Neagle on 2013-11-21.
Modified in Feb 2016 to add support for NSURLSession.
Updated June 2019 for compatibility with Python 3 and PyObjC 5.1.2+
Updated May 2022 for compatibilty with PyObjC 8.5 on macOS Mojave
Updated Feb 2025 to add support for Certificate Chains when using Client Certificates

curl replacement using NSURLConnection and friends

"""

from __future__ import absolute_import, print_function

import ctypes
import os
from urllib.parse import urlparse

# builtin super doesn't work with Cocoa classes in recent PyObjC releases.
# patch the credentialWithIdentity:certificates:persistence: signature
# see https://github.com/ronaldoussoren/pyobjc/issues/320#issuecomment-784278944
# more changes May 2022 to work around some issues with PyObjC 8.5 and
# macOS Mojave (and presumably earlier)
import objc
from asn1crypto.x509 import Certificate, Name
from CFNetwork import kCFNetworkProxiesHTTPEnable, kCFNetworkProxiesHTTPSEnable
from Foundation import (
    NSURL,
    NSBundle,
    NSDate,
    NSHTTPURLResponse,
    NSLog,
    NSMutableURLRequest,
    NSObject,
    NSRunLoop,
    NSURLCredential,
    NSURLCredentialPersistenceForSession,
    NSURLCredentialPersistenceNone,
    NSURLRequestReloadIgnoringLocalCacheData,
    NSURLResponseUnknownLength,
    NSURLSession,
    NSURLSessionConfiguration,
)
from objc import super
from Security import (
    SecCertificateCopyData,
    SecIdentityCopyCertificate,
    SecIdentityGetTypeID,
    SecItemCopyMatching,
    SecPolicyCreateBasicX509,
    SecTrustCreateWithCertificates,
    SecTrustEvaluateWithError,
    SecTrustGetCertificateAtIndex,
    SecTrustGetCertificateCount,
    errSecSuccess,
    kCFBooleanTrue,
    kSecClass,
    kSecClassIdentity,
    kSecMatchLimit,
    kSecMatchLimitAll,
    kSecReturnRef,
)

objc.registerCFSignature("SecIdentityRef", b"^{__SecIdentity=}", SecIdentityGetTypeID())
objc.registerMetaDataForSelector(
    b"NSURLCredential",
    b"credentialWithIdentity:certificates:persistence:",
    {
        "arguments": {
            2: {"null_accepted": False, "type": b"^{__SecIdentity=}"},
        },
        "classmethod": True,
        "hidden": False,
        "retval": {"_template": True, "type": b"@"},
    },
)

# NSURLSessionAuthChallengeDisposition enum constants
NSURLSessionAuthChallengeUseCredential = 0
NSURLSessionAuthChallengePerformDefaultHandling = 1
NSURLSessionAuthChallengeCancelAuthenticationChallenge = 2
NSURLSessionAuthChallengeRejectProtectionSpace = 3

# NSURLSessionResponseDisposition enum constants
NSURLSessionResponseCancel = 0
NSURLSessionResponseAllow = 1
NSURLSessionResponseBecomeDownload = 2

# TLS/SSLProtocol enum constants
kSSLProtocolUnknown = 0
kSSLProtocol3 = 2
kTLSProtocol1 = 4
kTLSProtocol11 = 7
kTLSProtocol12 = 8
kDTLSProtocol1 = 9

# define a helper function for block callbacks
CALLBACK_HELPER_AVAILABLE = True
try:
    _objc_so = ctypes.cdll.LoadLibrary(os.path.join(objc.__path__[0], "_objc.so"))
except OSError:
    # could not load _objc.so
    CALLBACK_HELPER_AVAILABLE = False
else:
    PyObjCMethodSignature_WithMetaData = _objc_so.PyObjCMethodSignature_WithMetaData
    PyObjCMethodSignature_WithMetaData.restype = ctypes.py_object

    def objc_method_signature(signature_str):
        """Return a PyObjCMethodSignature given a call signature in string
        format"""
        return PyObjCMethodSignature_WithMetaData(
            ctypes.create_string_buffer(signature_str), None, False
        )


# disturbing hack warning!
# this works around an issue with App Transport Security on 10.11
bundle = NSBundle.mainBundle()
info = bundle.localizedInfoDictionary() or bundle.infoDictionary()
info["NSAppTransportSecurity"] = {"NSAllowsArbitraryLoads": True}


def NSLogWrapper(message):
    """A wrapper function for NSLog to prevent format string errors"""
    NSLog("%@", message)


ssl_error_codes = {
    -9800: "SSL protocol error",
    -9801: "Cipher Suite negotiation failure",
    -9802: "Fatal alert",
    -9803: "I/O would block (not fatal)",
    -9804: "Attempt to restore an unknown session",
    -9805: "Connection closed gracefully",
    -9806: "Connection closed via error",
    -9807: "Invalid certificate chain",
    -9808: "Bad certificate format",
    -9809: "Underlying cryptographic error",
    -9810: "Internal error",
    -9811: "Module attach failure",
    -9812: "Valid cert chain, untrusted root",
    -9813: "Cert chain not verified by root",
    -9814: "Chain had an expired cert",
    -9815: "Chain had a cert not yet valid",
    -9816: "Server closed session with no notification",
    -9817: "Insufficient buffer provided",
    -9818: "Bad SSLCipherSuite",
    -9819: "Unexpected message received",
    -9820: "Bad MAC",
    -9821: "Decryption failed",
    -9822: "Record overflow",
    -9823: "Decompression failure",
    -9824: "Handshake failure",
    -9825: "Misc. bad certificate",
    -9826: "Bad unsupported cert format",
    -9827: "Certificate revoked",
    -9828: "Certificate expired",
    -9829: "Unknown certificate",
    -9830: "Illegal parameter",
    -9831: "Unknown Cert Authority",
    -9832: "Access denied",
    -9833: "Decoding error",
    -9834: "Decryption error",
    -9835: "Export restriction",
    -9836: "Bad protocol version",
    -9837: "Insufficient security",
    -9838: "Internal error",
    -9839: "User canceled",
    -9840: "No renegotiation allowed",
    -9841: "Peer cert is valid, or was ignored if verification disabled",
    -9842: "Server has requested a client cert",
    -9843: "Peer host name mismatch",
    -9844: "Peer dropped connection before responding",
    -9845: "Decryption failure",
    -9846: "Bad MAC",
    -9847: "Record overflow",
    -9848: "Configuration error",
    -9849: "Unexpected (skipped) record in DTLS",
}


class Gurl(NSObject):
    """A class for getting content from a URL
    using NSURLConnection/NSURLSession and friends"""

    def initWithOptions_(self, options):
        """Set up our Gurl object"""
        self = super(Gurl, self).init()
        if not self:
            return None

        self.follow_redirects = options.get("follow_redirects", False)
        self.ignore_system_proxy = options.get("ignore_system_proxy", False)
        self.can_resume = options.get("can_resume", False)
        self.url = options.get("url")
        self.additional_headers = options.get("additional_headers", {})
        self.username = options.get("username")
        self.password = options.get("password")
        self.download_only_if_changed = options.get("download_only_if_changed", False)
        self.connection_timeout = options.get("connection_timeout", 60)
        self.minimum_tls_protocol = options.get("minimum_tls_protocol", kTLSProtocol1)

        self.log = options.get("logging_function", NSLogWrapper)

        self.resume = False
        self.response = None
        self.headers = None
        self.status = None
        self.description = ""
        self.error = None
        self.SSLerror = None
        self.done = False
        self.redirection = []
        self.bytesReceived = 0
        self.expectedLength = -1
        self.percentComplete = 0
        self.connection = None
        self.session = None
        self.task = None
        self.received_data = bytearray()
        return self

    def start(self):
        """Start the connection"""
        url = NSURL.URLWithString_(self.url)
        request = NSMutableURLRequest.requestWithURL_cachePolicy_timeoutInterval_(
            url, NSURLRequestReloadIgnoringLocalCacheData, self.connection_timeout
        )
        if self.additional_headers:
            for header, value in self.additional_headers.items():
                request.setValue_forHTTPHeaderField_(value, header)

        configuration = NSURLSessionConfiguration.defaultSessionConfiguration()

        # optional: ignore system http/https proxies (10.9+ only)
        if self.ignore_system_proxy is True:
            configuration.setConnectionProxyDictionary_(
                {
                    kCFNetworkProxiesHTTPEnable: False,
                    kCFNetworkProxiesHTTPSEnable: False,
                }
            )

        # set minimum supported TLS protocol (defaults to TLS1)
        configuration.setTLSMinimumSupportedProtocol_(self.minimum_tls_protocol)

        self.session = NSURLSession.sessionWithConfiguration_delegate_delegateQueue_(
            configuration, self, None
        )
        self.task = self.session.dataTaskWithRequest_(request)
        self.task.resume()

    def cancel(self):
        """Cancel the connection"""
        if self.connection:
            self.session.invalidateAndCancel()
            self.done = True

    def isDone(self):
        """Check if the connection request is complete. As a side effect,
        allow the delegates to work by letting the run loop run for a bit"""
        if self.done:
            return self.done
        # let the delegates do their thing
        NSRunLoop.currentRunLoop().runUntilDate_(
            NSDate.dateWithTimeIntervalSinceNow_(0.1)
        )
        return self.done

    def recordError_(self, error):
        """Record any error info from completed connection/session"""
        self.error = error
        # If this was an SSL error, try to extract the SSL error code.
        if "NSUnderlyingError" in error.userInfo():
            ssl_code = (
                error.userInfo()["NSUnderlyingError"]
                .userInfo()
                .get("_kCFNetworkCFStreamSSLErrorOriginalValue", None)
            )
            if ssl_code:
                self.SSLerror = (
                    ssl_code,
                    ssl_error_codes.get(ssl_code, "Unknown SSL error"),
                )

    def URLSession_task_didCompleteWithError_(self, _session, _task, error):
        """NSURLSessionTaskDelegate method."""
        if error:
            self.recordError_(error)
        self.done = True

    def connection_didFailWithError_(self, _connection, error):
        """NSURLConnectionDelegate method
        Sent when a connection fails to load its request successfully."""
        self.recordError_(error)
        self.done = True

    def connectionDidFinishLoading_(self, _connection):
        """NSURLConnectionDataDelegate method
        Sent when a connection has finished loading successfully."""
        self.done = True

    def handleResponse_withCompletionHandler_(self, response, completionHandler):
        """Handle the response to the connection"""
        self.response = response
        self.bytesReceived = 0
        self.percentComplete = -1
        self.expectedLength = response.expectedContentLength()

        if response.className() == "NSHTTPURLResponse":
            # Headers and status code only available for HTTP/S transfers
            self.status = response.statusCode()
            self.description = NSHTTPURLResponse.localizedStringForStatusCode_(
                self.status
            )
            self.headers = dict(response.allHeaderFields())

        if completionHandler:
            # tell the session task to continue
            completionHandler(NSURLSessionResponseAllow)

    def URLSession_dataTask_didReceiveResponse_completionHandler_(
        self, _session, _task, response, completionHandler
    ):
        """NSURLSessionDataDelegate method"""
        if CALLBACK_HELPER_AVAILABLE:
            completionHandler.__block_signature__ = objc_method_signature(b"v@i")
        self.handleResponse_withCompletionHandler_(response, completionHandler)

    def connection_didReceiveResponse_(self, _connection, response):
        """NSURLConnectionDataDelegate delegate method
        Sent when the connection has received sufficient data to construct the
        URL response for its request."""
        self.handleResponse_withCompletionHandler_(response, None)

    def handleRedirect_newRequest_withCompletionHandler_(
        self, response, request, completionHandler
    ):
        """Handle the redirect request"""

        def allowRedirect():
            """Allow the redirect"""
            if completionHandler:
                completionHandler(request)
                return None
            return request

        def denyRedirect():
            """Deny the redirect"""
            if completionHandler:
                completionHandler(None)
            return None

        newURL = request.URL().absoluteString()
        if response is None:
            # the request has changed the NSURLRequest in order to standardize
            # its format, for example, changing a request for
            # http://www.apple.com to http://www.apple.com/. This occurs because
            # the standardized, or canonical, version of the request is used for
            # cache management. Pass the request back as-is
            # (it appears that at some point Apple also defined a redirect like
            # http://developer.apple.com to https://developer.apple.com to be
            # 'merely' a change in the canonical URL.)
            # Further -- it appears that this delegate method isn't called at
            # all in this scenario, unlike NSConnectionDelegate method
            # connection:willSendRequest:redirectResponse:
            # we'll leave this here anyway in case we're wrong about that
            self.log("Allowing redirect to: %s" % newURL)
            return allowRedirect()
        # If we get here, it appears to be a real redirect attempt
        # Annoyingly, we apparently can't get access to the headers from the
        # site that told us to redirect. All we know is that we were told
        # to redirect and where the new location is.
        self.redirection.append([newURL, dict(response.allHeaderFields())])
        newParsedURL = urlparse(newURL)
        # This code was largely based on the work of Andreas Fuchs
        # (https://github.com/munki/munki/pull/465)
        if self.follow_redirects is True or self.follow_redirects == "all":
            # Allow the redirect
            self.log("Allowing redirect to: %s" % newURL)
            return allowRedirect()
        elif self.follow_redirects == "https" and newParsedURL.scheme == "https":
            # Once again, allow the redirect
            self.log("Allowing redirect to: %s" % newURL)
            return allowRedirect()
        # If we're down here either the preference was set to 'none',
        # the url we're forwarding on to isn't https or follow_redirects
        # was explicitly set to False
        self.log("Denying redirect to: %s" % newURL)
        return denyRedirect()

    def URLSession_task_willPerformHTTPRedirection_newRequest_completionHandler_(
        self, _session, _task, response, request, completionHandler
    ):
        """NSURLSessionTaskDelegate method"""
        self.log(
            "URLSession_task_willPerformHTTPRedirection_newRequest_completionHandler_"
        )
        if CALLBACK_HELPER_AVAILABLE:
            completionHandler.__block_signature__ = objc_method_signature(b"v@@")
        self.handleRedirect_newRequest_withCompletionHandler_(
            response, request, completionHandler
        )

    def connection_willSendRequest_redirectResponse_(
        self, _connection, request, response
    ):
        """NSURLConnectionDataDelegate method
        Sent when the connection determines that it must change URLs in order
        to continue loading a request."""
        self.log("connection_willSendRequest_redirectResponse_")
        return self.handleRedirect_newRequest_withCompletionHandler_(
            response, request, None
        )

    # getCertRefs_ takes a certificate ref, and attempts to construct the certificate chain.
    # this requires that any certificates in the chain, are present in the Keychain.
    def getCertChainRefs_(self, cert_ref):
        status, trust = SecTrustCreateWithCertificates(
            cert_ref, SecPolicyCreateBasicX509(), None
        )
        if status != errSecSuccess:
            return None

        evaluated, evalErr = SecTrustEvaluateWithError(trust, None)
        if evalErr is not None:
            return None

        certRefs = []
        for i in range(0, SecTrustGetCertificateCount(trust), 1):
            certRefs.append(SecTrustGetCertificateAtIndex(trust, i))

        return certRefs

    def handleChallenge_withCompletionHandler_(self, challenge, completionHandler):
        """Handle an authentication challenge"""
        protectionSpace = challenge.protectionSpace()
        host = protectionSpace.host()
        realm = protectionSpace.realm()
        authenticationMethod = protectionSpace.authenticationMethod()
        self.log(
            "Authentication challenge for Host: %s Realm: %s AuthMethod: %s"
            % (host, realm, authenticationMethod)
        )
        if challenge.previousFailureCount() > 0:
            # we have the wrong credentials. just fail
            self.log("Previous authentication attempt failed.")
            if completionHandler:
                completionHandler(
                    NSURLSessionAuthChallengeCancelAuthenticationChallenge, None
                )
            else:
                challenge.sender().cancelAuthenticationChallenge_(challenge)

        # Handle HTTP Basic and Digest challenge
        if (
            self.username
            and self.password
            and authenticationMethod
            in [
                "NSURLAuthenticationMethodDefault",
                "NSURLAuthenticationMethodHTTPBasic",
                "NSURLAuthenticationMethodHTTPDigest",
            ]
        ):
            self.log("Will attempt to authenticate.")
            self.log(
                "Username: %s Password: %s"
                % (self.username, ("*" * len(self.password or "")))
            )
            credential = NSURLCredential.credentialWithUser_password_persistence_(
                self.username, self.password, NSURLCredentialPersistenceNone
            )
            if completionHandler:
                completionHandler(NSURLSessionAuthChallengeUseCredential, credential)
            else:
                challenge.sender().useCredential_forAuthenticationChallenge_(
                    credential, challenge
                )

        # Handle Client Certificate challenge
        elif authenticationMethod == "NSURLAuthenticationMethodClientCertificate":
            self.log("Client certificate required")

            # get issuers info from the response
            expected_issuer_dicts = []
            for dn in protectionSpace.distinguishedNames():
                raw = dn.bytes().tobytes()
                name = Name.load(raw)
                expected_issuer_dicts.append(dict(name.native))
                self.log(
                    "Accepted certificate-issuing authority: %s" % name.human_friendly
                )
            if not expected_issuer_dicts:
                self.log(
                    "The server didn't sent the list of "
                    "acceptable certificate-issuing authorities"
                )
                if completionHandler:
                    completionHandler(
                        NSURLSessionAuthChallengeCancelAuthenticationChallenge, None
                    )
                else:
                    challenge.sender().cancelAuthenticationChallenge_(challenge)

            # search for a matching identity (cert paired with private key)
            status, identity_refs = SecItemCopyMatching(
                {
                    kSecClass: kSecClassIdentity,
                    kSecReturnRef: kCFBooleanTrue,
                    kSecMatchLimit: kSecMatchLimitAll,
                },
                None,
            )
            if status != errSecSuccess:
                self.log("Could not list keychain certificates %s" % status)
                if completionHandler:
                    completionHandler(
                        NSURLSessionAuthChallengeCancelAuthenticationChallenge, None
                    )
                else:
                    challenge.sender().cancelAuthenticationChallenge_(challenge)
                # return since error getting certs from keychain
                # (identity_refs is None, crashes if we fall through to loop)
                return

            # loop through results to find cert that matches issuer
            for identity_ref in identity_refs:
                status, cert_ref = SecIdentityCopyCertificate(identity_ref, None)
                if status != errSecSuccess:
                    continue
                cert_data = SecCertificateCopyData(cert_ref)
                cert = Certificate.load(cert_data.bytes().tobytes())

                # includes the certificate issuer in the accepted subjects,
                # to retain pre-chain behaviour
                certSubjects = [dict(cert.native["tbs_certificate"]["issuer"])]

                # if we get a chain result back from the keychain
                # also use the subjects of issuing CAs as part of the trust evaluation
                certChainRefs = self.getCertChainRefs_(cert_ref)
                if certChainRefs is not None:
                    for c in certChainRefs:
                        cert_data = SecCertificateCopyData(c)
                        cert = Certificate.load(cert_data.bytes().tobytes())
                        certSubjects.append(
                            dict(cert.native["tbs_certificate"]["subject"])
                        )

                for certSubject in certSubjects:
                    if certSubject in expected_issuer_dicts:
                        self.log("Found matching identity")
                        break
                else:
                    continue
                # this break is only excuted if we found a certificate
                break
            else:
                self.log("Could not find matching identity")
                if completionHandler:
                    completionHandler(
                        NSURLSessionAuthChallengeCancelAuthenticationChallenge, None
                    )
                else:
                    challenge.sender().cancelAuthenticationChallenge_(challenge)
                # return since didn't find matching identity
                return

            self.log("Will attempt to authenticate")
            credential = (
                NSURLCredential.credentialWithIdentity_certificates_persistence_(
                    identity_ref, certChainRefs, NSURLCredentialPersistenceForSession
                )
            )
            if completionHandler:
                completionHandler(NSURLSessionAuthChallengeUseCredential, credential)
            else:
                challenge.sender().useCredential_forAuthenticationChallenge_(
                    credential, challenge
                )
        else:
            # fall back to system-provided default behavior
            self.log("Allowing OS to handle authentication request")
            if completionHandler:
                completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, None)
            else:
                if challenge.sender().respondsToSelector_(
                    "performDefaultHandlingForAuthenticationChallenge:"
                ):
                    self.log("Allowing OS to handle authentication request")
                    challenge.sender().performDefaultHandlingForAuthenticationChallenge_(
                        challenge
                    )
                else:
                    # Mac OS X 10.6 doesn't support
                    # performDefaultHandlingForAuthenticationChallenge:
                    self.log("Continuing without credential.")
                    challenge.sender().continueWithoutCredentialForAuthenticationChallenge_(
                        challenge
                    )

    def URLSession_task_didReceiveChallenge_completionHandler_(
        self, _session, _task, challenge, completionHandler
    ):
        """NSURLSessionTaskDelegate method"""
        if CALLBACK_HELPER_AVAILABLE:
            completionHandler.__block_signature__ = objc_method_signature(b"v@i@")
        self.log("URLSession_task_didReceiveChallenge_completionHandler_")
        self.handleChallenge_withCompletionHandler_(challenge, completionHandler)

    def handleReceivedData_(self, data):
        """Handle received data"""
        self.received_data.extend(data)
        self.bytesReceived += len(data)
        if self.expectedLength != NSURLResponseUnknownLength:
            self.percentComplete = int(
                float(self.bytesReceived) / float(self.expectedLength) * 100.0
            )

    def URLSession_dataTask_didReceiveData_(self, _session, _task, data):
        """NSURLSessionDataDelegate method"""
        self.handleReceivedData_(data)

    def connection_didReceiveData_(self, _connection, data):
        """NSURLConnectionDataDelegate method
        Sent as a connection loads data incrementally"""
        self.handleReceivedData_(data)
