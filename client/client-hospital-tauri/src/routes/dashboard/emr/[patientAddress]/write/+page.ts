import { error } from '@sveltejs/kit';
import type { PageLoad } from './$types';

export const prerender = false;

export const load: PageLoad = async ({ parent, params, url }) => {
	await parent();

	const accessToken = url.searchParams.get('accessToken');
	const patientPrePublicKey = url.searchParams.get('patientPrePublicKey');

	if (!accessToken || !patientPrePublicKey) {
		return error(404);
	}

	return {
		accessToken,
		delegationSignature: url.searchParams.get('delegationSignature'),
		patientIotaAddress: params.patientAddress,
		patientPrePublicKey,
		relatedRmeId: url.searchParams.get('relatedRmeId')
	};
};
