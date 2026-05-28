import type { DatasetCategory } from '$lib/types';
import type { PageLoad } from './$types';

export const prerender = false;
export const ssr = false;

export const load: PageLoad = async ({ parent, params }) => {
	await parent();

	return {
		datasetCategory: params.datasetCategory as DatasetCategory,
		relatedRmeId: params.emrIndex
	};
};
