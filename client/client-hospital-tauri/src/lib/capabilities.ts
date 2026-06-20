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
	return [...values].sort((a, b) => datasetCategories.indexOf(a) - datasetCategories.indexOf(b));
}

export function sortFunctions(values: FunctionCategory[]) {
	return [...values].sort((a, b) => functionCategories.indexOf(a) - functionCategories.indexOf(b));
}

export function delegableWriteFunctions(values: FunctionCategory[]) {
	return values.filter((value) => value !== 'ADMINISTRATIVE_GENERAL');
}

export function intersect<T>(left: readonly T[], right: readonly T[]) {
	const rightSet = new Set(right);
	return left.filter((value) => rightSet.has(value));
}

/** Read scope for clinical delegates must always include administrative snapshot segments. */
export function withMandatoryAdministrativeRead(functions: FunctionCategory[]) {
	const set = new Set<FunctionCategory>(functions);
	set.add('ADMINISTRATIVE_GENERAL');
	return sortFunctions([...set]);
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
	let rawReadDatasets: DatasetCategory[];
	let rawWriteDatasets: DatasetCategory[];
	let rawReadFunctions: FunctionCategory[];
	let rawWriteFunctions: FunctionCategory[];

	if (preset === 'doctor') {
		rawReadDatasets = [...datasetCategories];
		rawWriteDatasets = [...datasetCategories];
		rawReadFunctions = [...functionCategories];
		rawWriteFunctions = delegableWriteFunctions([...functionCategories]);
	} else if (preset === 'lab') {
		rawReadDatasets = [encounterDataset, 'LABORATORIUM'];
		rawWriteDatasets = ['LABORATORIUM'];
		rawReadFunctions = ['ADMINISTRATIVE_GENERAL', 'PEMERIKSAAN_PENUNJANG', 'LABORATORIUM'];
		rawWriteFunctions = ['LABORATORIUM'];
	} else if (preset === 'apotek') {
		rawReadDatasets = [encounterDataset, 'APOTEK'];
		rawWriteDatasets = ['APOTEK'];
		rawReadFunctions = ['ADMINISTRATIVE_GENERAL', 'TERAPI', 'PERESEPAN', 'DISPENSING'];
		rawWriteFunctions = ['PERESEPAN', 'DISPENSING'];
	} else {
		rawReadDatasets = [encounterDataset];
		rawWriteDatasets = [encounterDataset];
		rawReadFunctions = functionsForDataset(encounterDataset);
		rawWriteFunctions = ['ANAMNESIS', 'PEMERIKSAAN_FISIK', 'PEMERIKSAAN_PSIKOLOGIS'];
	}

	const readDatasets = readCapability
		? intersect(rawReadDatasets, readCapability.readDatasets)
		: rawReadDatasets;
	const writeDatasets = writeCapability
		? intersect(rawWriteDatasets, writeCapability.writeDatasets)
		: rawWriteDatasets;
	const readFunctions = readCapability
		? intersect(rawReadFunctions, readCapability.readFunctions)
		: rawReadFunctions;
	const writeFunctions = writeCapability
		? intersect(rawWriteFunctions, writeCapability.writeFunctions)
		: rawWriteFunctions;

	return {
		readDatasets: sortDatasets(unique(readDatasets)),
		writeDatasets: sortDatasets(unique(writeDatasets)),
		readFunctions: sortFunctions(unique(readFunctions)),
		writeFunctions: sortFunctions(unique(delegableWriteFunctions(writeFunctions)))
	};
}
