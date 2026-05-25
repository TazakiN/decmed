import { allowedSegmentFunctionCategories, datasetCategories, functionCategories } from './schema';
import type { AccessCapabilityData, DatasetCategory, FunctionCategory } from './types';

export const datasetLabels: Record<DatasetCategory, string> = {
	RAWAT_JALAN: 'Rawat Jalan',
	RAWAT_INAP: 'Rawat Inap',
	LABORATORIUM: 'Laboratorium',
	APOTEK: 'Apotek'
};

export const functionLabels: Record<FunctionCategory, string> = {
	ADMINISTRATIVE_GENERAL: 'Administrative General',
	ANAMNESIS: 'Anamnesis',
	PEMERIKSAAN_FISIK: 'Pemeriksaan Fisik',
	PEMERIKSAAN_PSIKOLOGIS: 'Pemeriksaan Psikologis',
	RIWAYAT_PENGGUNAAN_OBAT: 'Riwayat Penggunaan Obat',
	RENCANA_RAWAT: 'Rencana Rawat',
	PERENCANAAN_PEMULANGAN: 'Perencanaan Pemulangan',
	INSTRUKSI_MEDIK_DAN_KEPERAWATAN: 'Instruksi Medik dan Keperawatan',
	PEMERIKSAAN_PENUNJANG: 'Pemeriksaan Penunjang',
	DIAGNOSIS: 'Diagnosis',
	INFORMED_CONSENT: 'Informed Consent',
	TERAPI: 'Terapi',
	LABORATORIUM: 'Laboratorium',
	PERESEPAN: 'Peresepan',
	DISPENSING: 'Dispensing'
};

export type DelegationPreset = 'nurse' | 'doctor' | 'lab' | 'apotek';
export type DelegationMode = 'read' | 'write' | 'read_write';

export const presetItems: { value: DelegationPreset; label: string }[] = [
	{ value: 'nurse', label: 'Perawat' },
	{ value: 'doctor', label: 'Dokter' },
	{ value: 'lab', label: 'Laboratorium' },
	{ value: 'apotek', label: 'Apotek' }
];

export function functionsForDataset(dataset: DatasetCategory) {
	return [...allowedSegmentFunctionCategories[dataset]] as FunctionCategory[];
}

export function sortDatasets(values: DatasetCategory[]) {
	return [...values].sort(
		(a, b) => datasetCategories.indexOf(a) - datasetCategories.indexOf(b)
	);
}

export function sortFunctions(values: FunctionCategory[]) {
	return [...values].sort(
		(a, b) => functionCategories.indexOf(a) - functionCategories.indexOf(b)
	);
}

export function intersect<T>(left: readonly T[], right: readonly T[]) {
	const rightSet = new Set(right);
	return left.filter((value) => rightSet.has(value));
}

export function unique<T>(values: readonly T[]) {
	return [...new Set(values)];
}

export function isReadableCapability(capability: AccessCapabilityData) {
	return capability.purpose === 'Read' && capability.readDatasets.length > 0;
}

export function isWritableCapability(capability: AccessCapabilityData) {
	return capability.purpose === 'Update' && capability.writeDatasets.length > 0;
}

export function presetScope({
	preset,
	encounterDataset,
	readCapability,
	writeCapability
}: {
	preset: DelegationPreset;
	encounterDataset: DatasetCategory;
	readCapability?: AccessCapabilityData;
	writeCapability?: AccessCapabilityData;
}) {
	const rawDatasets =
		preset === 'lab'
			? (['LABORATORIUM'] as DatasetCategory[])
			: preset === 'apotek'
				? (['APOTEK'] as DatasetCategory[])
				: preset === 'doctor'
					? ([encounterDataset, 'LABORATORIUM', 'APOTEK'] as DatasetCategory[])
					: ([encounterDataset] as DatasetCategory[]);

	const rawFunctions =
		preset === 'lab'
			? (['LABORATORIUM'] as FunctionCategory[])
			: preset === 'apotek'
				? (['PERESEPAN', 'DISPENSING'] as FunctionCategory[])
				: preset === 'doctor'
					? ([
							'ANAMNESIS',
							'PEMERIKSAAN_FISIK',
							'DIAGNOSIS',
							'TERAPI',
							'LABORATORIUM',
							'PERESEPAN',
							'DISPENSING'
						] as FunctionCategory[])
					: ([
							'ANAMNESIS',
							'PEMERIKSAAN_FISIK',
							'PEMERIKSAAN_PSIKOLOGIS'
						] as FunctionCategory[]);

	const readDatasets = readCapability
		? intersect(rawDatasets, readCapability.readDatasets)
		: rawDatasets;
	const writeDatasets = writeCapability
		? intersect(rawDatasets, writeCapability.writeDatasets)
		: rawDatasets;
	const readFunctions = readCapability
		? intersect(rawFunctions, readCapability.readFunctions)
		: rawFunctions;
	const writeFunctions = writeCapability
		? intersect(rawFunctions, writeCapability.writeFunctions)
		: rawFunctions;

	return {
		readDatasets: sortDatasets(unique(readDatasets)),
		writeDatasets: sortDatasets(unique(writeDatasets)),
		readFunctions: sortFunctions(unique(readFunctions)),
		writeFunctions: sortFunctions(unique(writeFunctions))
	};
}

