import { v4 as uuid } from 'uuid';

/**
 * Creates a random ID for use in XML document references. Some parsers
 * require the ID not to start with a number, so we use an underscore prefix
 */
export default function randomID() {
	return "_" + uuid();
};
