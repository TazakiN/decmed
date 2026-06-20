import { error } from '@sveltejs/kit';
import type { PageLoad } from './$types';

export const prerender = false;

export const load: PageLoad = async ({ parent, params, url }) => {
	await parent();

	const patientIotaAddress = params.patientAddress;
	const accessToken = url.searchParams.get('accessToken');

	if (!accessToken) {
		error(404, 'accessToken required');
	}

	return {
		accessToken,
		dataPreSecretKeySeedCapsule: url.searchParams.get('dataPreSecretKeySeedCapsule'),
		delegationSignature: url.searchParams.get('delegationSignature'),
		encDataPreSecretKeySeed: url.searchParams.get('encDataPreSecretKeySeed'),
		patientIotaAddress,
		patientName: url.searchParams.get('patientName')
	};
};
