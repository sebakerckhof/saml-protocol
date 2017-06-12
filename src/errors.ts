import ExtendableError from 'es6-error';
 
class SamlError extends ExtendableError {
	sp: any
	idp: any
	payload: any

	constructor (message, sp?, idp?, payload?) {
		super(message);

		this.message = message;

		// add extended debug data in function bindings in case anyone's error
		// handler tries to serialize one of these.
		this.sp = sp;
		this.idp = idp;
		this.payload = payload;
	}

	get SP(){
		return this.sp;
	}

	get IDP(){
		return this.idp;
	}

	get Payload(){
		return this.payload;
	}
}
/**
 * Errors thrown when one or more conditions invalidated an assertion
 * or request. Groups an array of validation errors.
 */
class ValidationError extends SamlError {
	errors: string[]

	constructor (message, errors, sp, idp, payload) {
		super(message, sp, idp, payload);

		this.errors = errors || [message];
	}
}

/**
 * Errors thrown when an issue completely prevents the SAML protocol from
 * functioning - primairly entity configuration.
 */
class ProtocolError extends SamlError {
}

/**
 * Thrown when an IDP rejects an auth request
 */
class RejectionError extends SamlError {
}

export {
	ValidationError,
	ProtocolError,
	RejectionError
}