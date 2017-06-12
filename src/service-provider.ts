import errors from "./errors";
import metadata from "./metadata";
import requestConstruction from "./request-construction";
import requestHandling from "./request-handling";
import responseConstruction from "./response-construction";
import responseHandling from "./response-handling";
import protocolBindings from "./protocol-bindings";

import Provider, { Model, EndPoint, Endpoints, ProviderConfig } from './provider';
import { IDPProviderConfig } from './identity-provider';

export interface SPModel extends Model {
	getIdentityProvider(entityID: string) : Promise<IDPProviderConfig>
}

export interface SPEndPoints extends Endpoints {
	loginRequest: EndPoint | string,
}

export interface SPProviderConfig extends ProviderConfig {
	endpoints: SPEndPoints,
}

type Method = "POST" | "GET";

export default class IdentityProvider extends Provider {
  
	constructor(model: IDPModel, config: IDPProviderConfig){
		super(model, config);
	}

 
	produceMetadata(shouldSign?: boolean) : string {
    return metadata.buildSPMetadata(this.config, (shouldSign === undefined) ? true : shouldSign);
  }

  static parseMetadata(xml: string) : SPProviderConfig{
    return metadata.getSPFromMetadata(xml);
  }
}
	
IdentityProvider.prototype.getSPFromMetadata = function(xml) {
	return metadata.getSPFromMetadata(xml);

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
