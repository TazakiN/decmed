import type { PageLoad } from './$types';

export const prerender = false;
export const ssr = false;

export const load: PageLoad = async ({ parent, params }) => {
	await parent();

	const emrIndex = parseInt(params.emrIndex);

	return { emrIndex };
};
