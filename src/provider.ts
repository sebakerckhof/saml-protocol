import errors from "./errors";
import metadata from "./metadata";
import requestConstruction from "./request-construction";
import requestHandling from "./request-handling";
import responseConstruction from "./response-construction";
import responseHandling from "./response-handling";
import protocolBindings from "./protocol-bindings";


export interface Model {
	storeRequestID(requestID: string, requestType: string, provider: ProviderConfig) : Promise<boolean>
	verifyRequestID(requestID: string, requestType: string, provider: ProviderConfig) : Promise<boolean>
	invalidateRequestID(requestID: string, requestType: string, provider: ProviderConfig) : Promise<boolean>
	getNow?(): Date
}

export type CredentialUse = "signing" | "encryption";

export interface Credential {
	certificate: string,
	publicKey?: string,
	privateKey?: string,
	privateKeyPassword?: string,
	use?: CredentialUse
}

export interface EndPoint {
	post?: string,
	redirect?: string
}

export interface EndPoints {
	logoutRequest?: EndPoint | string,
	logoutResponse?: EndPoint | string, 
}

export interface ExpandedEndPoints {
	logoutRequest?: EndPoint,
	logoutResponse?: EndPoint, 
}

export interface Algorithms {
	signing?: string[],
	encryption?: string[],
	keyEncryption?: string[]
}

export interface ProviderConfig {
	entityID: string
	credentials: (Credential | string)[] ,
	endpoints: EndPoints,
	algorithms?: Algorithms,
	nameIDFormats?: string[],
	signAllRequests?: boolean,
	signAllResponses?: boolean,
	requireSignedRequests?: boolean,
	requireSignedResponses?: boolean,
	requireEncryptedRequests?: boolean,
	encryptAllRequests?: boolean
	requireEncryptedResponses?: boolean,
	encryptAllResponses?: boolean
	responseLatencyInSecs?: Number
}

type Method = "POST" | "GET";

export interface SamlResponse {
	method: Method,
	url?: string,
	contentType: string,
	formBody?: any
}

export interface NameID{
	format: string,
	allowCreate: boolean
}

export interface SamlRequest {
	idp: Provider
	sp: Provider,
	requestID: string,
	nameID: NameID
}

export interface Attribute {
	name: string,
	friendlyName: string,
	values: any[]
}

export interface SamlAuthResponse {
	idp: Method,
	nameID: string,
	nameIDFormat: string,
	attributes: Attribute[]
}

export default abstract class Provider {
  
	model: Model;
  config: ProviderConfig;
	
	constructor(model: Model, config: ProviderConfig){
		this.model = model;
		this.config = config;
	}

	produceLogoutRequest(provider) : SamlRequest{
		return requestConstruction.createBoundLogoutRequest(this.config, provider, this.model);
	}

	produceLogoutResponse(provider, inResponseTo, nameID){
		
	}

	consumePostLogoutResponse(formParams : any){
		const response = protocolBindings.getDataFromPostBinding(formParams);
		return responseHandling.processResponse(this.model, this.config, response);
	}

	consumeRedirectLogoutResponse(queryParams : any){
		const response = protocolBindings.getDataFromRedirectBinding(queryParams);
		return responseHandling.processResponse(this.model, this.config, response);
	}

	produceFailureResponse(sp, inResponseTo, errorMessage) {
		return responseConstruction.buildBoundAuthnFailureResponse(sp, this.idp, this.model, inResponseTo, errorMessage);
	}

	abstract produceMetadata() : string
}


class ServiceProvider{
	constructor()
}
function ServiceProvider (config, model) {
	this.sp = config;
	this.model = model;
}

function IdentityProvider (config, model) {
	this.idp = config;
	this.model = model;
}

ServiceProvider.prototype.produceAuthnRequest = function(idp) {
	return requestConstruction.createBoundAuthnRequest(this.sp, idp, this.model);
};

ServiceProvider.prototype.consumePostResponse = function(formParams) {
	const response = protocolBindings.getDataFromPostBinding(formParams);
	return responseHandling.processResponse(this.model, this.sp, response);
};

ServiceProvider.prototype.consumeRedirectResponse = function(queryParams) {
	const response = protocolBindings.getDataFromRedirectBinding(queryParams);
	return responseHandling.processResponse(this.model, this.sp, response);
};

ServiceProvider.prototype.produceSPMetadata = function(shouldSign) {
	return metadata.buildSPMetadata(this.sp, (shouldSign === undefined) ? true : shouldSign);
};

ServiceProvider.prototype.getIDPFromMetadata = function(xml) {
	return metadata.getIDPFromMetadata(xml);
};

IdentityProvider.prototype.consumePostAuthnRequest = function(formParams) {
	const request = protocolBindings.getDataFromPostBinding(formParams);
	return requestHandling.processAuthnRequest(this.model, this.idp, request);
};

IdentityProvider.prototype.consumeRedirectAuthnRequest = function(queryParams) {
	const request = protocolBindings.getDataFromRedirectBinding(queryParams);
	return requestHandling.processAuthnRequest(this.model, this.idp, request);
};

IdentityProvider.prototype.produceSuccessResponse = function(sp, inResponseTo, nameID, attributes) {
	return responseConstruction.buildBoundSuccessResponse(sp, this.idp, this.model, inResponseTo, nameID, attributes);
};

IdentityProvider.prototype.produceFailureResponse = function(sp, inResponseTo, errorMessage) {
	return responseConstruction.buildBoundAuthnFailureResponse(sp, this.idp, this.model, inResponseTo, errorMessage);
};

IdentityProvider.prototype.produceIDPMetadata = function(shouldSign) {
	return metadata.buildIDPMetadata(this.idp, (shouldSign === undefined) ? true : shouldSign);
};

IdentityProvider.prototype.getSPFromMetadata = function(xml) {
	return metadata.getSPFromMetadata(xml);
};
