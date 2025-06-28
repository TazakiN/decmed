import type { PageLoad } from './$types';

export const load: PageLoad = async ({ parent, params }) => {
	await parent();

	let patientAddress = params.patientAddress;

	return {
		patientAddress
	};
};
