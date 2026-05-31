import type { TauriPatientPrivateAdministrativeData } from './types';

/** Payload shape for ADMINISTRATIVE_GENERAL RME segments (snake_case). */
export type AdministrativeGeneralSegmentPayload = TauriPatientPrivateAdministrativeData;

export function isAdministrativeGeneralPayload(
	payload: Record<string, unknown> | undefined
): payload is AdministrativeGeneralSegmentPayload {
	if (!payload || typeof payload !== 'object') return false;
	return typeof payload.id === 'string' && payload.id.trim().length > 0;
}

/**
 * Parse segment payload for ADMINISTRATIVE_GENERAL.
 * Supports structured admin fields; legacy `{ text }` returns null.
 */
export function parseAdministrativeGeneralPayload(
	payload: Record<string, unknown> | undefined
): AdministrativeGeneralSegmentPayload | null {
	if (isAdministrativeGeneralPayload(payload)) {
		return payload;
	}
	return null;
}
