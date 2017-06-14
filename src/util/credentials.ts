import { pki } from "node-forge";
import { ProviderConfig, CredentialUse } from '../provider';
import { isString } from 'lodash';
// credential resolution and transformation functions

export {
	getCredentialsFromEntity,
	getPublicKeyFromCertificate,
	decryptPrivateKey
}

/**
 * Generic credentials accessor - gets a list of signing or encryption
 * credentials from an SP or an IDP.
 * @param entity: IDP or SP configuration
 * @param use: one of "signing" or "encryption"
 * @return: an array of suitable credentials as defined in the configuration
 */
function getCredentialsFromEntity(entity: ProviderConfig, use: CredentialUse) {
	if (!entity.credentials) {
		entity.credentials = [];
	}
	return entity.credentials.filter(credential => ((credential.use === undefined) || (credential.use == use)));
}

/**
 * Derives a public key from an X509 certificate
 * @param certificate: an X509 certificate in PEM format (with headers)
 * @return: a public key in PEM format (with headers)
 */
function getPublicKeyFromCertificate(certificate: string) {
	const cert = pki.certificateFromPem(certificate);
	return pki.publicKeyToPem(cert.publicKey);
}

/**
 * Decrypts encrypted RSA private key
 * @param key: an encrypted RSA private key
 * @param passphrase: passphrase to decrypt RSA key
 * @return: unencrypted private key
 */
function decryptPrivateKey(key: string, passphrase?: string): string {
	return isString(passphrase) ?
		pki.privateKeyToPem(pki.decryptRsaPrivateKey(String(key), passphrase))
		: key;
}

