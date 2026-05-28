import type { DatasetCategory, FunctionCategory } from './types';

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

const datasetOrder: DatasetCategory[] = ['RAWAT_JALAN', 'RAWAT_INAP', 'LABORATORIUM', 'APOTEK'];
const functionOrder: FunctionCategory[] = [
	'ADMINISTRATIVE_GENERAL',
	'ANAMNESIS',
	'PEMERIKSAAN_FISIK',
	'PEMERIKSAAN_PSIKOLOGIS',
	'RIWAYAT_PENGGUNAAN_OBAT',
	'RENCANA_RAWAT',
	'PERENCANAAN_PEMULANGAN',
	'INSTRUKSI_MEDIK_DAN_KEPERAWATAN',
	'PEMERIKSAAN_PENUNJANG',
	'DIAGNOSIS',
	'INFORMED_CONSENT',
	'TERAPI',
	'LABORATORIUM',
	'PERESEPAN',
	'DISPENSING'
];

export function compareDatasets(left: DatasetCategory, right: DatasetCategory) {
	return orderValue(datasetOrder, left) - orderValue(datasetOrder, right);
}

export function compareFunctions(left: FunctionCategory, right: FunctionCategory) {
	return orderValue(functionOrder, left) - orderValue(functionOrder, right);
}

export function formatDateTime(value: string) {
	const date = new Date(value);

	if (Number.isNaN(date.getTime())) {
		return value;
	}

	return date.toLocaleDateString('id-ID', {
		year: 'numeric',
		month: 'short',
		day: 'numeric',
		hour: 'numeric',
		minute: 'numeric',
		hourCycle: 'h23'
	});
}

export function timeValue(value: string) {
	const time = new Date(value).getTime();
	return Number.isNaN(time) ? 0 : time;
}

export function payloadToText(payload: Record<string, unknown> | undefined) {
	if (!payload || Object.keys(payload).length === 0) {
		return '-';
	}

	if (typeof payload.text === 'string') {
		return payload.text;
	}

	return valueToText(payload);
}

function orderValue<T>(values: readonly T[], value: T) {
	const index = values.indexOf(value);
	return index === -1 ? Number.MAX_SAFE_INTEGER : index;
}

function labelFromKey(key: string) {
	return key
		.replace(/_/g, ' ')
		.replace(/([a-z])([A-Z])/g, '$1 $2')
		.replace(/\b\w/g, (char) => char.toUpperCase());
}

function valueToText(value: unknown): string {
	if (typeof value === 'string') {
		return value;
	}

	if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
		return String(value);
	}

	if (value === null || value === undefined) {
		return '-';
	}

	if (Array.isArray(value)) {
		if (value.length === 0) {
			return '-';
		}

		return value.map((item) => valueToText(item)).join('\n');
	}

	if (typeof value === 'object') {
		const entries = Object.entries(value as Record<string, unknown>);

		if (entries.length === 0) {
			return '-';
		}

		return entries
			.map(([key, entryValue]) => {
				const text = valueToText(entryValue);

				if (text.includes('\n')) {
					return `${labelFromKey(key)}:\n${text
						.split('\n')
						.map((line) => `  ${line}`)
						.join('\n')}`;
				}

				return `${labelFromKey(key)}: ${text}`;
			})
			.join('\n');
	}

	return String(value);
}
