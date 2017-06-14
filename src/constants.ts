enum Foo { X = 4 }
const namespace = {
	saml = "urn:oasis:names:tc:SAML:2.0:assertion",
	samlp = "urn:oasis:names:tc:SAML:2.0:protocol",
	"md" = "urn:oasis:names:tc:SAML:2.0:metadata",
	"ds" = "http://www.w3.org/2000/09/xmldsig#",
	"xenc" = "http://www.w3.org/2001/04/xmlenc#",
	"xs" = "http://www.w3.org/2001/XMLSchema",
	"xsi" = "http://www.w3.org/2001/XMLSchema-instance"
}

const protocol = {
	"NAMEIDFORMAT": {
		"EMAILADDRESS": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		"UNSPECIFIED": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		"PERSISTENT": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		"TRANSIENT": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		"KERBEROS": "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
		"ENTITY": "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	},
	"BINDINGS": {
		"REDIRECT": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		"POST": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	},
	"STATUS": {
		"SUCCESS": "urn:oasis:names:tc:SAML:2.0:status:Success",
		"REQUESTER": "urn:oasis:names:tc:SAML:2.0:status:Requester",
		"RESPONDER": "urn:oasis:names:tc:SAML:2.0:status:Responder",
		"VERSIONMISMATCH": "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch",
		"AUTHNFAILED": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
		"INVALIDATTRNAMEORVALUE": "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue",
		"INVALIDNAMEIDPOLICY": "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
		"NOAUTHNCONTEXT": "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
		"NOAVAILABLEIDP": "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP",
		"NOPASSIVE": "urn:oasis:names:tc:SAML:2.0:status:NoPassive",
		"NOSUPPORTEDIDP": "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP",
		"PARTIALLOGOUT": "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
		"PROXYCOUNTEXCEEDED": "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded",
		"REQUESTDENIED": "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
		"REQUESTUNSUPPORTED": "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported",
		"REQUESTVERSIONDEPRECATED": "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated",
		"REQUESTVERSIONTOOHIGH": "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh",
		"REQUESTVERSIONTOOLOW": "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow",
		"RESOURCENOTRECOGNIZED": "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized",
		"TOOMANYRESPONSES": "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses",
		"UNKNOWNATTRPROFILE": "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile",
		"UNKNOWNPRINCIPAL": "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
		"UNSUPPORTEDBINDING": "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
	},
	"AUTHNCONTEXT": {
		"PASSWORD": "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
		"PASSWORDPROTECTEDTRANSPORT": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		"TLSCLIENT": "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient",
		"X509": "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
		"WINDOWS": "urn:federation:authentication:windows",
		"KERBEROS": "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"
	},
	"CONFIRMATIONMETHODS": {
		"HOLDEROFKEY": "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
		"SENDERVOUCHES": "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches",
		"BEARER": "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	},
	"ATTRNAMEFORMAT": {
		"BASIC": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	},
	"default_attribute_mapping": {
		"email": [
			"EmailAddress", "Email", "email_address", "mail",
			"urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
		],
		"first_name": [
			"FirstName", "given_name", "GivenName",
			"urn:oid:2.5.4.42"
		],
		"last_name": [
			"LastName", "family_name", "FamilyName",
			"urn:oid:2.5.4.4"
		]
	}
}


/**
* @file urn.ts
* @author tngan
* @desc  Includes all keywords need in express-saml2
*/
const namespace = {
  binding: {
    redirect: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
    post: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    artifact: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'
  },
  names: {
    protocol: 'urn:oasis:names:tc:SAML:2.0:protocol',
    assertion: 'urn:oasis:names:tc:SAML:2.0:assertion',
    metadata: 'urn:oasis:names:tc:SAML:2.0:metadata',
    userLogout: 'urn:oasis:names:tc:SAML:2.0:logout:user',
    adminLogout: 'urn:oasis:names:tc:SAML:2.0:logout:admin'
  },
  authnContextClassRef: {
    password: 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
    passwordProtectedTransport: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
  },
  format: {
    emailAddress: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    persistent: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    transient: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    entity: 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
    unspecified: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    kerberos: 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
    windowsDomainQualifiedName: 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName',
    x509SubjectName: 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName'
  },
  statusCode: {
    // permissible top-level status codes
    success: 'urn:oasis:names:tc:SAML:2.0:status:Success',
    requester: 'urn:oasis:names:tc:SAML:2.0:status:Requester',
    responder: 'urn:oasis:names:tc:SAML:2.0:status:Responder',
    versionMismatch: 'urn:oasis:names:tc:SAML:2.0:status:VersionMismatch',
    // second-level status codes
    authFailed: 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
    invalidAttrNameOrValue: 'urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue',
    invalidNameIDPolicy: 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy',
    noAuthnContext: 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext',
    noAvailableIDP: 'urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP',
    noPassive: 'urn:oasis:names:tc:SAML:2.0:status:NoPassive',
    noSupportedIDP: 'urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP',
    partialLogout: 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
    proxyCountExceeded: 'urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded',
    requestDenied: 'urn:oasis:names:tc:SAML:2.0:status:RequestDenied',
    requestUnsupported: 'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported',
    requestVersionDeprecated: 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated',
    requestVersionTooHigh: 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh',
    requestVersionTooLow: 'urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow',
    resourceNotRecognized: 'urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized',
    tooManyResponses: 'urn:oasis:names:tc:SAML:2.0:status:TooManyResponses',
    unknownAttrProfile: 'urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile',
    unknownPrincipal: 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal',
    unsupportedBinding: 'urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding'
  }
};

const 
const tags = {
  request: {
    AllowCreate: '{AllowCreate}',
    AssertionConsumerServiceURL: '{AssertionConsumerServiceURL}',
    AuthnContextClassRef: '{AuthnContextClassRef}',
    AssertionID: '{AssertionID}',
    Audience: '{Audience}',
    AuthnStatement: '{AuthnStatement}',
    AttributeStatement: '{AttributeStatement}',
    ConditionsNotBefore: '{ConditionsNotBefore}',
    ConditionsNotOnOrAfter: '{ConditionsNotOnOrAfter}',
    Destination: '{Destination}',
    EntityID: '{EntityID}',
    ID: '{ID}',
    Issuer: '{Issuer}',
    IssueInstant: '{IssueInstant}',
    InResponseTo: '{InResponseTo}',
    NameID: '{NameID}',
    NameIDFormat: '{NameIDFormat}',
    ProtocolBinding: '{ProtocolBinding}',
    SessionIndex: '{SessionIndex}',
    SubjectRecipient: '{SubjectRecipient}',
    SubjectConfirmationDataNotOnOrAfter: '{SubjectConfirmationDataNotOnOrAfter}',
    StatusCode: '{StatusCode}'
  },
  xmlTag: {
    loginRequest: 'AuthnRequest',
    logoutRequest: 'LogoutRequest',
    loginResponse: 'Response',
    logoutResponse: 'LogoutResponse'
  }
};

const algorithms = {
  signature: {
    RSA_SHA1: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    RSA_SHA256: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    RSA_SHA512: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
  },
  encryption: {
    data: {
      AES_128: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',
      AES_256: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
      TRI_DEC: 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'
    },
    key: {
      RSA_OAEP_MGF1P: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
      RSA_1_5: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
    }
  },
  digest: {
    'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'http://www.w3.org/2000/09/xmldsig#sha1',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'http://www.w3.org/2001/04/xmlenc#sha256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'http://www.w3.org/2001/04/xmlenc#sha512' // support hashing algorithm sha512 in xml-crypto after 0.8.0
  }
};

const wording = {
  urlParams: {
    samlRequest: 'SAMLRequest',
    samlResponse: 'SAMLResponse',
    logoutRequest: 'LogoutRequest',
    logoutResponse: 'LogoutResponse',
    sigAlg: 'SigAlg',
    signature: 'Signature',
    relayState: 'RelayState'
  },
  binding: {
    redirect: 'redirect',
    post: 'post',
    artifact: 'artifact'
  },
  certUse: {
    signing: 'signing',
    encrypt: 'encryption'
  },
  metadata: {
    sp: 'metadata-sp',
    idp: 'metadata-idp'
  }
};

// https://wiki.shibboleth.net/confluence/display/CONCEPT/MetadataForSP
// some idps restrict the order of elements in entity descriptors
const elementsOrder = {
  default: ['KeyDescriptor', 'NameIDFormat', 'SingleLogoutService', 'AssertionConsumerService'],
  onelogin: ['KeyDescriptor', 'NameIDFormat', 'SingleLogoutService', 'AssertionConsumerService'],
  shibboleth: ['KeyDescriptor', 'SingleLogoutService', 'NameIDFormat', 'AssertionConsumerService', 'AttributeConsumingService']
};

export { namespace, tags, algorithms, wording, elementsOrder };
