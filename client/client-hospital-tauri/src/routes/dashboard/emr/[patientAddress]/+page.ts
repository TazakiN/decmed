import { error } from '@sveltejs/kit';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ parent, params, url }) => {
	await parent();

	const patientIotaAddress = params.patientAddress;
	const accessToken = url.searchParams.get('accessToken');
	const index = url.searchParams.get('index');

	if (!accessToken || !index) {
		return error(404);
	}

	return {
		accessToken,
		dataPreSecretKeySeedCapsule: url.searchParams.get('dataPreSecretKeySeedCapsule'),
		encDataPreSecretKeySeed: url.searchParams.get('encDataPreSecretKeySeed'),
		patientIotaAddress,
		index: isNaN(parseInt(index)) ? 0 : parseInt(index)
	};
};
