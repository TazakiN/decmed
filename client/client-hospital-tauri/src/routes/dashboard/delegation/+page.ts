import type { PageLoad } from './$types';

export const load: PageLoad = async ({ parent, url }) => {
	const { role } = await parent();
	const patientAddress = url.searchParams.get('patientAddress');

	return { patientAddress, role };
};
