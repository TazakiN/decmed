<script lang="ts">
	import { ADMINISTRATIVE_PERSONNEL_ROLE } from '$lib/constants';
	import type { SuccessResponse, TauriAccessData } from '$lib/types';
	import { tryCatchAsVal } from '$lib/utils';
	import { invoke } from '@tauri-apps/api/core';
	import { toast } from 'svelte-sonner';

	type Preset = 'nurse' | 'doctor' | 'lab' | 'apotek';

	let { data } = $props();

	let writeAccess = $state<TauriAccessData[]>([]);
	let selectedAccessIndex = $state(0);
	let selectedAccess = $derived(writeAccess[selectedAccessIndex]);
	let preset = $state<Preset>('doctor');
	let delegateeAddress = $state('');
	let delegateePrePublicKey = $state('');
	let generatedRelatedRmeId = $state<string | null>(null);

	const isAdminPersonnel = $derived(data.role === ADMINISTRATIVE_PERSONNEL_ROLE);

	const loadAccess = async () => {
		if (!isAdminPersonnel) return;

		const res = await tryCatchAsVal(async () => {
			return (await invoke('get_update_access_administrative_personnel')) as SuccessResponse<
				TauriAccessData[]
			>;
		});
		if (!res.success) {
			toast.error(res.error);
			return;
		}
		writeAccess = res.data.data;

		if (data.patientAddress) {
			const selectedIndex = writeAccess.findIndex(
				(access) => access.patientIotaAddress === data.patientAddress
			);
			selectedAccessIndex = selectedIndex >= 0 ? selectedIndex : 0;
		}
	};

	const delegateAccess = async () => {
		const entry = selectedAccess;
		if (!entry) {
			toast.error('Write access pasien tidak ditemukan');
			return;
		}
		if (!delegateeAddress.trim() || !delegateePrePublicKey.trim()) {
			toast.error('Isi alamat dan PRE public key delegatee');
			return;
		}

		const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

		const res = await tryCatchAsVal(async () => {
			return (await invoke('create_admin_delegated_access', {
				payload: {
					parentWriteToken: entry.accessToken,
					delegateeIotaAddress: delegateeAddress.trim(),
					delegateePrePublicKey: delegateePrePublicKey.trim(),
					patientIotaAddress: entry.patientIotaAddress,
					patientName: entry.patientName,
					patientPrePublicKey: entry.patientPrePublicKey,
					parentEncDataPreSecretKeySeed: entry.encDataPreSecretKeySeed ?? '',
					parentDataPreSecretKeySeedCapsule: entry.dataPreSecretKeySeedCapsule ?? '',
					expiresBefore: expires,
					preset
				}
			})) as SuccessResponse<{ relatedRmeId: string }>;
		});

		if (!res.success) {
			toast.error(res.error);
			return;
		}

		generatedRelatedRmeId = res.data.data.relatedRmeId;
		toast.success(`Delegasi berhasil. RME ID: ${generatedRelatedRmeId}`);
	};

	$effect(() => {
		void data.role;
		void loadAccess();
	});
</script>

<div class="flex flex-col gap-4 p-4">
	<h2 class="font-montserrat text-xl font-medium">Delegasi Akses</h2>

	{#if !isAdminPersonnel}
		<p>Halaman ini hanya untuk Administrative Personnel.</p>
	{:else}
		{#if selectedAccess}
			<div class="border border-zinc-200 rounded p-3">
				<p class="font-medium">{selectedAccess.patientName}</p>
				<p class="text-xs text-zinc-600 truncate">{selectedAccess.patientIotaAddress}</p>
			</div>
		{:else if writeAccess.length === 0}
			<p class="text-sm text-zinc-600">Belum ada write access dari pasien.</p>
		{:else}
			<p class="text-sm text-zinc-600">Write access pasien yang dipilih tidak ditemukan.</p>
		{/if}

		<label class="flex flex-col gap-1">
			<span>Preset delegasi</span>
			<select class="border p-2 rounded" bind:value={preset}>
				<option value="nurse">Perawat (anamnesis/pemeriksaan)</option>
				<option value="doctor">Dokter (diagnosis/terapi/lab/resep)</option>
				<option value="lab">Laboratorium</option>
				<option value="apotek">Apotek (resep/dispensing)</option>
			</select>
		</label>

		<p class="text-sm text-zinc-600">
			Episode RAWAT diwarisi dari write token parent. RME ID baru dibuat otomatis saat delegasi.
		</p>
		{#if generatedRelatedRmeId}
			<p class="text-sm font-medium">Related RME ID: {generatedRelatedRmeId}</p>
		{/if}

		<label class="flex flex-col gap-1">
			<span>Delegatee IOTA address</span>
			<input class="border p-2 rounded" bind:value={delegateeAddress} />
		</label>
		<label class="flex flex-col gap-1">
			<span>Delegatee PRE public key (base64)</span>
			<input class="border p-2 rounded" bind:value={delegateePrePublicKey} />
		</label>

		<button type="button" class="button-dark" onclick={delegateAccess}>Delegasi</button>
	{/if}
</div>
