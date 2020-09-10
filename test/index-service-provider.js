import { should, expect } from 'chai';
import { DOMParser, XMLSerializer } from 'xmldom';
import { URLSearchParams } from 'url';
import xpath from 'xpath';
import zlib from 'zlib';

import { ServiceProvider, IdentityProvider } from '../lib';
import * as responseConstruction from '../lib/response-construction';
import * as protocolBindings from '../lib/protocol-bindings';
import { RejectionError } from '../lib/errors';
import * as metadata from '../lib/metadata';
import * as encryption from '../lib/util/encryption';
import * as signing from '../lib/util/signing';

import entityFixtures from './fixtures/entities';
import credentialFixtures from './fixtures/credentials';
import ModelStub from './fixtures/model-stub';
import samlFixtures from './fixtures/saml';

should();

describe('ServiceProvider', function () {
  describe('produceAuthnRequest', function () {
    let model;
    beforeEach(function () {
      model = new ModelStub();
    });

    it('produces a valid POST-bound AuthnRequest descriptor for a POST-accepting IDP', async function () {
      const sp = new ServiceProvider(entityFixtures.simpleSP, model);
      const idp = entityFixtures.simpleIDP;

      const descriptor = await sp.produceAuthnRequest(idp);
      descriptor.should.not.be.null;
      descriptor.method.should.equal('POST');
      descriptor.contentType.should.equal('x-www-form-urlencoded');
      descriptor.formBody.should.not.be.null;
      descriptor.formBody.SAMLRequest.should.not.be.null;
      descriptor.url.should.not.be.null;
      descriptor.url.href.should.equal(idp.endpoints.login.post);

      const requestBase64 = descriptor.formBody.SAMLRequest;
      const requestXML = Buffer.from(requestBase64, 'base64').toString('utf8');
      const request = new DOMParser().parseFromString(requestXML);
      xpath.select("//*[local-name(.)='AuthnRequest']", request).length.should.equal(1);
      xpath.select("//*[local-name(.)='Signature']", request).length.should.equal(0);
    });

    it('produces a valid signed POST-bound AuthnRequest descriptor for a POST-accepting IDP', async function () {
      const sp = new ServiceProvider(entityFixtures.simpleSPWithCredentials, model);
      const idp = entityFixtures.simpleIDPWithCredentials;

      const descriptor = await sp.produceAuthnRequest(idp);
      descriptor.should.not.be.null;
      descriptor.method.should.equal('POST');
      descriptor.contentType.should.equal('x-www-form-urlencoded');
      descriptor.formBody.should.not.be.null;
      descriptor.formBody.SAMLRequest.should.not.be.null;
      descriptor.url.should.not.be.null;
      descriptor.url.href.should.equal(idp.endpoints.login);

      const requestBase64 = descriptor.formBody.SAMLRequest;
      const requestXML = Buffer.from(requestBase64, 'base64').toString('utf8');
      const request = new DOMParser().parseFromString(requestXML);
      xpath.select("//*[local-name(.)='AuthnRequest']", request).length.should.equal(1);
      xpath.select("//*[local-name(.)='Signature']", request).length.should.equal(1);
      const sigNode = xpath.select("//*[local-name(.)='Signature']", request)[0];
      signing.validateXMLSignature(requestXML, sigNode, sp.sp.credentials[0]).should.equal(0);
    });

    it('produces a valid REDIRECT-bound AuthnRequest descriptor for a REDIRECT-accepting IDP', async function () {
      const sp = new ServiceProvider(entityFixtures.simpleSP, model);
      const idp = entityFixtures.oneloginRedirectIDP;

      const descriptor = await sp.produceAuthnRequest(idp);
      descriptor.should.not.be.null;
      descriptor.method.should.equal('GET');
      descriptor.url.should.not.be.null;
      descriptor.url.href.startsWith(idp.endpoints.login.redirect).should.be.true;
      descriptor.url.searchParams.should.not.be.null;
      descriptor.url.searchParams.get('SAMLRequest').should.not.be.null;
      expect(descriptor.url.searchParams.get('Signature')).to.be.null;
      const requestBase64 = descriptor.url.searchParams.get('SAMLRequest');
      const requestXML = zlib.inflateRawSync(Buffer.from(requestBase64, 'base64')).toString('utf8');
      const request = new DOMParser().parseFromString(requestXML);
      xpath.select("//*[local-name(.)='AuthnRequest']", request).length.should.equal(1);
    });

    it('produces a valid signed REDIRECT-bound AuthnRequest descriptor for a REDIRECT-accepting IDP', async function () {
      const sp = new ServiceProvider(entityFixtures.simpleSPWithCredentials, model);
      const idp = entityFixtures.oneloginRedirectIDP;

      const descriptor = await sp.produceAuthnRequest(idp);
      descriptor.should.not.be.null;
      descriptor.method.should.equal('GET');
      descriptor.url.should.not.be.null;
      descriptor.url.href.startsWith(idp.endpoints.login.redirect).should.be.true;
      descriptor.url.searchParams.should.not.be.null;
      descriptor.url.searchParams.get('SAMLRequest').should.not.be.null;
      descriptor.url.searchParams.get('Signature').should.not.be.null;
      const requestBase64 = descriptor.url.searchParams.get('SAMLRequest');
      const requestXML = zlib.inflateRawSync(Buffer.from(requestBase64, 'base64')).toString('utf8');
      const request = new DOMParser().parseFromString(requestXML);
      xpath.select("//*[local-name(.)='AuthnRequest']", request).length.should.equal(1);

      signing.verifyURLSignature(
        sp.sp.credentials[0].certificate,
        protocolBindings.constructSignaturePayload(descriptor.url.searchParams),
        descriptor.url.searchParams.get('SigAlg'),
        descriptor.url.searchParams.get('Signature'),
      ).should.equal(true);
    });
  });

  describe('consumePostResponse', function () {
    let model;

    beforeEach(function () {
      // spoof a state of having sent the request for this response
      model = ModelStub.whichResolvesIDP(entityFixtures.oneloginIDP);
      model.storeRequestID('ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685', entityFixtures.oneloginIDP);
    });

    function signResponse(xml) {
      return signing.signXML(
        xml,
        {
          reference: "//*[local-name(.)='Response']/*[local-name(.)='Issuer']",
          action: 'after',
        },
        "//*[local-name(.)='Response']",
        entityFixtures.oneloginIDP.credentials[0],
      );
    }

    function signAssertion(xml) {
      return signing.signXML(
        xml,
        {
          reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
          action: 'after',
        },
        "//*[local-name(.)='Assertion']",
        entityFixtures.oneloginIDP.credentials[0],
      );
    }

    async function encryptAssertion(xml) {
      const doc = new DOMParser().parseFromString(xml);
      const cred = entityFixtures.oneloginSP.credentials[0];
      const encryptedAssertion = await encryption.encryptAssertion(doc, cred);
      return new XMLSerializer().serializeToString(encryptedAssertion);
    }

    function prepareAsPostRequest(responsePayload) {
      const responseBase64 = Buffer.from(responsePayload, 'utf8').toString('base64');
      const formParams = { SAMLResponse: responseBase64 };
      return formParams;
    }

    it('consumes a valid unsigned POST response', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: false,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const postResponse = await prepareAsPostRequest(responsePayload);
      const descriptor = await sp.consumePostResponse(postResponse);
      descriptor.should.not.be.null;
      descriptor.idp.should.equal(entityFixtures.oneloginIDP);
      descriptor.nameID.should.not.be.null;
      descriptor.attributes.should.not.be.null;
      descriptor.attributes.length.should.equal(3);
    });

    it('consumes a valid POST response without Name ID', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: false,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response-nonameid.xml');
      const postResponse = await prepareAsPostRequest(responsePayload);
      const descriptor = await sp.consumePostResponse(postResponse);
      descriptor.should.not.be.null;
      descriptor.idp.should.equal(entityFixtures.oneloginIDP);
      expect(descriptor.nameID).to.be.undefined;
      descriptor.attributes.should.not.be.null;
      descriptor.attributes.length.should.equal(3);
    });

    it('consumes a valid POST response with a signature in the Response element', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: true,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const signedPayload = await signResponse(responsePayload);
      const postResponse = await prepareAsPostRequest(signedPayload);
      const descriptor = await sp.consumePostResponse(postResponse);
      descriptor.should.not.be.null;
      descriptor.idp.should.equal(entityFixtures.oneloginIDP);
      descriptor.nameID.should.not.be.null;
      descriptor.attributes.should.not.be.null;
      descriptor.attributes.length.should.equal(3);
    });

    it('consumes a valid POST response with a signature in the Assertion element', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: true,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const signedPayload = await signAssertion(responsePayload);
      const postResponse = await prepareAsPostRequest(signedPayload);
      const descriptor = await sp.consumePostResponse(postResponse);
      descriptor.should.not.be.null;
      descriptor.idp.should.equal(entityFixtures.oneloginIDP);
      descriptor.nameID.should.not.be.null;
      descriptor.attributes.should.not.be.null;
      descriptor.attributes.length.should.equal(3);
    });

    it('consumes a valid encrypted POST response', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: false,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const encryptedPayload = await encryptAssertion(responsePayload);
      const postResponse = await prepareAsPostRequest(encryptedPayload);
      const descriptor = await sp.consumePostResponse(postResponse);
      descriptor.should.not.be.null;
      descriptor.idp.should.equal(entityFixtures.oneloginIDP);
      descriptor.nameID.should.not.be.null;
      descriptor.attributes.should.not.be.null;
      descriptor.attributes.should.have.lengthOf(3);
    });

    it('consumes a valid encrypted POST response with a signed assertion', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: true,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const signedPayload = await signAssertion(responsePayload);
      const encryptedAndSignedPayload = await encryptAssertion(signedPayload);
      const postResponse = await prepareAsPostRequest(encryptedAndSignedPayload);
      const descriptor = await sp.consumePostResponse(postResponse);
      descriptor.should.not.be.null;
      descriptor.idp.should.equal(entityFixtures.oneloginIDP);
      descriptor.nameID.should.not.be.null;
      descriptor.attributes.should.not.be.null;
      descriptor.attributes.length.should.equal(3);
    });

    it('consumes a valid double-signed, encrypted, POST response', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: true,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const signedPayload = await signAssertion(responsePayload);
      const encryptedAndSignedPayload = await encryptAssertion(signedPayload);
      const signedEncryptedSignedPayload = await signResponse(encryptedAndSignedPayload);
      const postResponse = await prepareAsPostRequest(signedEncryptedSignedPayload);
      const descriptor = await sp.consumePostResponse(postResponse);
      descriptor.should.not.be.null;
      descriptor.idp.should.equal(entityFixtures.oneloginIDP);
      descriptor.nameID.should.not.be.null;
      descriptor.attributes.should.not.be.null;
      descriptor.attributes.length.should.equal(3);
    });

    it('rejects an invalid unsigned POST response', async function () {
      // destination and other attributes will not match as we chose a different SP
      const sp = new ServiceProvider(
        {
          ...entityFixtures.simpleSP,
          requireSignedResponses: true,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const postResponse = await prepareAsPostRequest(responsePayload);
      try {
        await sp.consumePostResponse(postResponse);
      } catch (error) {
        error.should.not.be.null;
        error.message.should.have.string('invalid assertion');
        error.errors.join(',').should.have.string('destination');
      }
    });

    it('rejects an otherwise-valid POST response with an invalid signature', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: true,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const signedPayload = await signResponse(responsePayload);
      const doc = new DOMParser().parseFromString(signedPayload);
      xpath.select("//*[local-name(.)='AttributeValue']", doc)[0].textContent = 'changed';
      const xml = new XMLSerializer().serializeToString(doc);
      const postResponse = await prepareAsPostRequest(xml);
      try {
        await sp.consumePostResponse(postResponse);
      } catch (error) {
        error.should.not.be.null;
        error.message.should.have.string('invalid assertion');
        error.errors.join(',').should.have.string('signature');
      }
    });

    it('rejects an POST response without a signature when one is required', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: true,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      try {
        const postResponse = await prepareAsPostRequest(responsePayload);
        await sp.consumePostResponse(postResponse);
      } catch (error) {
        error.should.not.be.null;
        error.message.should.have.string('invalid assertion');
        error.errors.join(',').should.have.string('signature');
      }
    });

    it('rejects a response that indicates an error occurred with a RejectionError', async function () {
      const sp = new ServiceProvider(entityFixtures.oneloginSP, model);
      const failurePayload = responseConstruction.createAuthnFailureResponse(
        sp.sp,
        entityFixtures.oneloginIDP,
        'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
        'Something bad happened',
        sp.sp.endpoints.assert,
      );

      try {
        const postResponse = await prepareAsPostRequest(failurePayload);
        await sp.consumePostResponse(postResponse);
      } catch (error) {
        error.should.not.be.null;
        expect(error instanceof RejectionError);
        error.message.should.have.string('IDP rejected AuthnRequest');
        error.message.should.have.string('Something bad happened');
      }
    });
  });

  describe('consumeRedirectResponse', function () {
    let model;

    beforeEach(function () {
      // spoof a state of having sent the request for this response
      model = ModelStub.whichResolvesIDP(entityFixtures.oneloginIDP);
      model.storeRequestID('ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685', entityFixtures.oneloginIDP);
    });

    function signAssertion(xml) {
      return signing.signXML(
        xml,
        {
          reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
          action: 'after',
        },
        "//*[local-name(.)='Assertion']",
        entityFixtures.oneloginIDP.credentials[0],
      );
    }

    async function encryptAssertion(xml) {
      const doc = new DOMParser().parseFromString(xml);
      const cred = entityFixtures.oneloginSP.credentials[0];
      const encryptedAssertion = await encryption.encryptAssertion(doc, cred);
      return new XMLSerializer().serializeToString(encryptedAssertion);
    }

    function prepareAsRedirectRequest(xml) {
      // deflate, encode
      const responsePayload = zlib.deflateRawSync(xml).toString('base64');
      return new URLSearchParams({
        SAMLResponse: responsePayload,
        RelayState: 'some-string',
      });
    }

    function signRedirectRequest(queryParams) {
      // compute signature
      const sigAlg = signing.supportedAlgorithms[0];
      const sigCredential = entityFixtures.oneloginIDP.credentials[0];

      queryParams.set('SigAlg', sigAlg);

      const payload = protocolBindings.constructSignaturePayload(queryParams);
      const signature = signing.createURLSignature(sigCredential.privateKey, payload, sigAlg);

      // apply query parameters
      queryParams.set('Signature', signature);
      return queryParams;
    }

    it('consumes a valid unsigned REDIRECT response', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: false,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const redirectResponse = await prepareAsRedirectRequest(responsePayload);
      const descriptor = await sp.consumeRedirectResponse(redirectResponse);
      descriptor.should.not.be.null;
      descriptor.idp.should.equal(entityFixtures.oneloginIDP);
      descriptor.nameID.should.not.be.null;
      descriptor.attributes.should.not.be.null;
      descriptor.attributes.length.should.equal(3);
    });

    it('rejects an otherwise-valid unsigned REDIRECT response if expecting a signature', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: true,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const redirectResponse = await prepareAsRedirectRequest(responsePayload);
      try {
        await sp.consumeRedirectResponse(redirectResponse);
      } catch (error) {
        error.should.not.be.null;
        error.errors[0].should.have.string('signature');
      }
    });

    it('consumes a valid REDIRECT response with a query signature', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: true,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const redirectResponse = await prepareAsRedirectRequest(responsePayload);
      const signedResponse = await signRedirectRequest(redirectResponse);
      const descriptor = await sp.consumeRedirectResponse(signedResponse);
      descriptor.should.not.be.null;
      descriptor.idp.should.equal(entityFixtures.oneloginIDP);
      descriptor.nameID.should.not.be.null;
      descriptor.attributes.should.not.be.null;
      descriptor.attributes.length.should.equal(3);
    });

    it('consumes a valid REDIRECT response with a query signature and an Assertion signature', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: true,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const signedAssertion = await signAssertion(responsePayload);
      const redirectRequest = await prepareAsRedirectRequest(signedAssertion);
      const signedRequest = await signRedirectRequest(redirectRequest);
      const descriptor = await sp.consumeRedirectResponse(signedRequest);
      descriptor.should.not.be.null;
      descriptor.idp.should.equal(entityFixtures.oneloginIDP);
      descriptor.nameID.should.not.be.null;
      descriptor.attributes.should.not.be.null;
      descriptor.attributes.length.should.equal(3);
    });

    it('consumes a valid REDIRECT response with a query signature and an encrypted Assertion', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: true,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const encryptedAssertion = await encryptAssertion(responsePayload);
      const redirectRequest = await prepareAsRedirectRequest(encryptedAssertion);
      const signedRequest = await signRedirectRequest(redirectRequest);
      const descriptor = await sp.consumeRedirectResponse(signedRequest);
      descriptor.should.not.be.null;
      descriptor.idp.should.equal(entityFixtures.oneloginIDP);
      descriptor.nameID.should.not.be.null;
      descriptor.attributes.should.not.be.null;
      descriptor.attributes.length.should.equal(3);
    });

    it('consumes a valid REDIRECT response with a query signature, an Assertion signature, and an encrypted Assertion', async function () {
      const sp = new ServiceProvider(
        {
          ...entityFixtures.oneloginSP,
          requireSignedResponses: true,
        },
        model,
      );

      const responsePayload = samlFixtures('onelogin/onelogin-saml-response.xml');
      const signedAssertion = await signAssertion(responsePayload);
      const signedAndEncryptedAssertion = await encryptAssertion(signedAssertion);
      const redirectRequest = await prepareAsRedirectRequest(signedAndEncryptedAssertion);
      const signedRequest = await signRedirectRequest(redirectRequest);
      const descriptor = await sp.consumeRedirectResponse(signedRequest);
      descriptor.should.not.be.null;
      descriptor.idp.should.equal(entityFixtures.oneloginIDP);
      descriptor.nameID.should.not.be.null;
      descriptor.attributes.should.not.be.null;
      descriptor.attributes.length.should.equal(3);
    });

    it('rejects a response that indicates an error occurred with a RejectionError', async function () {
      const sp = new ServiceProvider(entityFixtures.oneloginSP, model);
      const failurePayload = responseConstruction.createAuthnFailureResponse(
        sp.sp,
        entityFixtures.oneloginIDP,
        'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
        'Something bad happened',
        sp.sp.endpoints.assert,
      );

      const redirectRequest = await prepareAsRedirectRequest(failurePayload);
      try {
        await sp.consumeRedirectResponse(redirectRequest);
      } catch (error) {
        error.should.not.be.null;
        expect(error instanceof RejectionError);
        error.message.should.have.string('IDP rejected AuthnRequest');
        error.message.should.have.string('Something bad happened');
      }
    });
  });

  describe('produceSPMetadata', function () {
    it('should produce a metadata descriptor describing a simple SP', function () {
      const sp = new ServiceProvider(entityFixtures.simpleSP, null);
      const md = sp.produceSPMetadata();
      md.should.not.be.null;

      const spConfFromData = metadata.getSPFromMetadata(md);
      spConfFromData.entityID.should.equal(sp.sp.entityID);
      spConfFromData.credentials.length.should.equal(0);
    });

    it('should produce a metadata descriptor describing a complex SP', function () {
      const spConf = {
        entityID: 'test.saml.com',
        credentials: [
          {
            use: 'signing',
            certificate: credentialFixtures.sp1.certificate,
            privateKey: credentialFixtures.sp1.privateKey,
          },
          {
            use: 'encryption',
            certificate: credentialFixtures.sp2.certificate,
            privateKey: credentialFixtures.sp2.privateKey,
          },
        ],
        endpoints: {
          assert: {
            redirect: 'test.saml.com/assert/redirect',
            post: 'test.saml.com/assert/redirect',
          },
          logout: {
            redirect: 'test.saml.com/logout/redirect',
            post: 'test.saml.com/logout/redirect',
          },
        },
        signAllRequests: true,
        requireSignedResponses: true,
      };

      const sp = new ServiceProvider(spConf, null);
      const md = sp.produceSPMetadata();
      md.should.not.be.null;
      // md.should.equal(`entityID="test.saml.com" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_212193ea69dc927b87d5a3f9c3ed0c3f85c076fc20"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>Iv8QlbOohdM06Na1UAlzCuvMbI8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>kXswQjouFxxaiXy5jt8tiojcUzdswNaOBCypIu7xW1MIzTtZsnl2hHNtZNatDRJKS5x40U4OExhSwmF8iBbiSsCNHFpGa90uqeTv9wLk9cr02qEXMfvLWBLv4+vj4mhnJHbhVCRxW7Mm7ByvRUE6c48r6sxicoNqoH13g5f+3nYRruVTDeBScYZhg5Y3AIvPaGzNVsTfFTQSfZpmwLAQPwcfxgqB9Q+kBEJi/j7+4G/jPLc55VZTyQBt28MnXPK+e20BVVNdXVihzRwyAWN/i3NrO8rj+eO67KoK3GKfSZpHE55uQsE3CnP6slXaeDFnG6KzbcmkAvULstDrQVcK/Q==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAowCCQDL+eawbnMNhzANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkRDMRMwEQYDVQQHEwpXYXNoaW5ndG9uMRYwFAYDVQQKEw1Tb2NpYWwgVGFibGVzMRcwFQYDVQQLEw5JbmZyYXN0cnVjdHVyZTExMC8GCSqGSIb3DQEJARYicm9iZXJ0LmJyb3duc3RlaW5Ac29jaWFsdGFibGVzLmNvbTAeFw0xNjA2MDcxNTE1MjFaFw0xNzA2MDcxNTE1MjFaMIGTMQswCQYDVQQGEwJVUzELMAkGA1UECBMCREMxEzARBgNVBAcTCldhc2hpbmd0b24xFjAUBgNVBAoTDVNvY2lhbCBUYWJsZXMxFzAVBgNVBAsTDkluZnJhc3RydWN0dXJlMTEwLwYJKoZIhvcNAQkBFiJyb2JlcnQuYnJvd25zdGVpbkBzb2NpYWx0YWJsZXMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvJF5YuTmf9m30UfRih+klHhNEfkOzloAEUlqF9dyaP84qN8yrhys1HYFxvVJpsWWu5PoUPeXvg6LiNyfBnFOskG65hcSoz4qpHGlRhQ96mVHU8zfQz/fp9eyHteHJ2BU809/i1COVfgdE59MbZDPE+CYxqMP9LyDmAMJ2e06etOXj36Ok0elbCeCYE4rRwX9292ziuXHayEijCKNXizn9IbPYqc8eqAKv4NdEmvU0MocV60wvVdgBHVx9yWumVxoBQWJ2LqDKav0HzAaF9iFWH14+S7JNE07YyK0JRDqvxZFFit46ZEbqpWv3NKvnnCPM3YuyapPjXLkFvZJMMwujwIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAQp9g8KADDCRqFgeBJJY97VN/q2dLqEr1jTMYmHLqVQAm1weKbHMxNSVoYolIuarWdbzSKTZkJB/eEb7edQxQSg+Uul/ukPoqSpWjbuEnQRY4mItTlgq09ErBwdKZVq/WLymrE82ScEtqDrMQTCFHPLAV7ICOk6iaJpGkhsKrQinKlIlAOiO0d1xgllprSJu2jPb6Z6zb4btnFHct5U+yfrHdQIckeR9+KR1BAn+I82/Q2wMIgNXR9rmTby/jymXsjUcDtOJoOuWyQVJkSLg0YmABHwd+yIESCQ6T/jpiPj22jv4tALS4i/iu4BLwk3SflmcsM8HOIo4JMSBqDKz7J</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><md:SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAowCCQDL+eawbnMNhzANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkRDMRMwEQYDVQQHEwpXYXNoaW5ndG9uMRYwFAYDVQQKEw1Tb2NpYWwgVGFibGVzMRcwFQYDVQQLEw5JbmZyYXN0cnVjdHVyZTExMC8GCSqGSIb3DQEJARYicm9iZXJ0LmJyb3duc3RlaW5Ac29jaWFsdGFibGVzLmNvbTAeFw0xNjA2MDcxNTE1MjFaFw0xNzA2MDcxNTE1MjFaMIGTMQswCQYDVQQGEwJVUzELMAkGA1UECBMCREMxEzARBgNVBAcTCldhc2hpbmd0b24xFjAUBgNVBAoTDVNvY2lhbCBUYWJsZXMxFzAVBgNVBAsTDkluZnJhc3RydWN0dXJlMTEwLwYJKoZIhvcNAQkBFiJyb2JlcnQuYnJvd25zdGVpbkBzb2NpYWx0YWJsZXMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvJF5YuTmf9m30UfRih+klHhNEfkOzloAEUlqF9dyaP84qN8yrhys1HYFxvVJpsWWu5PoUPeXvg6LiNyfBnFOskG65hcSoz4qpHGlRhQ96mVHU8zfQz/fp9eyHteHJ2BU809/i1COVfgdE59MbZDPE+CYxqMP9LyDmAMJ2e06etOXj36Ok0elbCeCYE4rRwX9292ziuXHayEijCKNXizn9IbPYqc8eqAKv4NdEmvU0MocV60wvVdgBHVx9yWumVxoBQWJ2LqDKav0HzAaF9iFWH14+S7JNE07YyK0JRDqvxZFFit46ZEbqpWv3NKvnnCPM3YuyapPjXLkFvZJMMwujwIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAQp9g8KADDCRqFgeBJJY97VN/q2dLqEr1jTMYmHLqVQAm1weKbHMxNSVoYolIuarWdbzSKTZkJB/eEb7edQxQSg+Uul/ukPoqSpWjbuEnQRY4mItTlgq09ErBwdKZVq/WLymrE82ScEtqDrMQTCFHPLAV7ICOk6iaJpGkhsKrQinKlIlAOiO0d1xgllprSJu2jPb6Z6zb4btnFHct5U+yfrHdQIckeR9+KR1BAn+I82/Q2wMIgNXR9rmTby/jymXsjUcDtOJoOuWyQVJkSLg0YmABHwd+yIESCQ6T/jpiPj22jv4tALS4i/iu4BLwk3SflmcsM8HOIo4JMSBqDKz7J</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICpDCCAYwCCQCuOTQslbup7DANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMTYwNjA3MTUxNzU3WhcNMTcwNjA3MTUxNzU3WjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtWYTCtOijIBeS4gnM2+hDkCndX4Ejtvezgbb4FtTCcVKN3+ZL1IiNQjtPWuyOykPqSaF6VXYsDnrE8HOxi82bLrOgNTB30gsBpPnXQtdiWrmHBoeUYYwcrlrCSPYRSmscIb9f0oLgWmbZhtxri2Grcap1CedAAaFWuh+3lWijb5kxL5Ic2TcI3hztJwd4MU+g0kiaABP7k/cBaBiwEQPfoabpG3QfFt8gVFVAqjQcMWAHFWjO9FmapEEKs64XW+8JAYLMf9sImea/iI9ycDRxqjkJrcRx95j+bme5LmMMjmLW9DTjirv4nVHfXj5cdDqf6ZcsjYbYq6h5uhig/YuJAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAJ1Uk8lqaayuzsryowzoads67gMYu7VTlth/2d+i3S2zLfIea0KJUeb86WBUJHtVnlTslaRjNr0kRtvBGTF3ycf9nJFMqvj1u/ew3sU6hilxqrt4Q/uoLGMXbaeXYUW6hvFiXM7mB8elPxAhO+XJu0CgBmd2+3CoGRPmRN12/F3vUI5sLkA+lSwdVZpWXJqzz9uPgeJfxkmLsNYAtHQnKkDU5Yg/gs1ZDH8dEIp3nEvYFBBQy/kbtG/MS3os3q1e4DWwKshYZ0oHqz/ubw2TUG+Y4SZ7STPgVoc9ny15bElR/IlSz5frmj4KeuohZO4UfrgJV2avFIFEO/cZgOoTRRg=</ds:X509Certificate></ds:X509Data></ds:KeyInfo><md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/><md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/><md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="test.saml.com/logout/redirect" ResponseLocation="test.saml.com/logout/redirect"/><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="test.saml.com/logout/redirect" ResponseLocation="test.saml.com/logout/redirect"/><md:AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="test.saml.com/assert/redirect"/><md:AssertionConsumerService index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="test.saml.com/assert/redirect"/></md:SPSSODescriptor></md:EntityDescriptor>`); // eslint-disable-line
      const spConfFromData = metadata.getSPFromMetadata(md);
      spConfFromData.entityID.should.equal(spConf.entityID);
      spConfFromData.credentials.length.should.equal(2);
      spConfFromData.credentials.forEach((credential) => {
        credential.certificate.should.not.be.null;
        expect(credential.privateKey).to.be.undefined;
      });

      spConfFromData.requireSignedResponses.should.be.true;
    });
  });

  describe('getIDPFromMetadata', function () {
    it('should produce an IDP config suitable for further use when provided metadata', function () {
      const md = samlFixtures('ssocircle/ssocircle-metadata.xml');
      const sp = new ServiceProvider(entityFixtures.simpleSP, null);
      const idp = sp.getIDPFromMetadata(md);
      idp.should.not.be.null;
      idp.entityID.should.equal('http://idp.ssocircle.com');
      idp.credentials.length.should.equal(2);
      idp.endpoints.login.should.exist;
    });
  });

  describe('should be able to complete an SSO flow with IdentityProvider', function () {
    it('should learn about an IDP through metadata and do SSO', async function () {
      const spModel = new ModelStub();
      const idpModel = new ModelStub();

      const sp = new ServiceProvider(entityFixtures.simpleSPWithCredentials, spModel);
      const idp = new IdentityProvider(entityFixtures.simpleIDPWithCredentials, idpModel);

      const spMD = sp.produceSPMetadata();
      const idpMD = idp.produceIDPMetadata();

      spModel.idpStub = sp.getIDPFromMetadata(idpMD);
      idpModel.spStub = idp.getSPFromMetadata(spMD);

      const userNameID = '123456789';
      const userAttributes = {
        FirstName: 'Bobby',
        LastName: 'Tables',
        EmailAddress: 'bobby@saml.com',
      };

      const spRequestDescriptor = await sp.produceAuthnRequest(spModel.idpStub);
      spRequestDescriptor.method.should.equal('POST');
      spRequestDescriptor.formBody.should.not.be.null;

      const idpRequestDescriptor = await idp.consumePostAuthnRequest(spRequestDescriptor.formBody);
      idpRequestDescriptor.sp.should.equal(idpModel.spStub);
      idpRequestDescriptor.requestID.should.not.be.null;
      idpRequestDescriptor.nameID.format.should.equal('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');

      const idpResponseDescriptor = await idp.produceSuccessResponse(
        idpModel.spStub,
        idpRequestDescriptor.requestID,
        userNameID,
        userAttributes,
      );
      idpResponseDescriptor.method.should.equal('POST');
      idpResponseDescriptor.formBody.should.not.be.null;

      const spResponseDescriptor = await sp.consumePostResponse(idpResponseDescriptor.formBody);
      spResponseDescriptor.idp.should.equal(spModel.idpStub);
      spResponseDescriptor.nameID.should.equal(userNameID);
      spResponseDescriptor.attributes.should.not.be.null;
      spResponseDescriptor.attributes.length.should.equal(3);
    });
  });
});
