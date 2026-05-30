<script lang="ts">
	import {
		datasetLabels,
		functionLabels,
		intersect,
		isReadableCapability,
		isWritableCapability,
		presetItems,
		presetScope,
		sortDatasets,
		sortFunctions,
		type DelegationMode,
		type DelegationPreset
	} from '$lib/capabilities';
	import type {
		AccessCapabilitiesResponse,
		AccessCapabilityData,
		DatasetCategory,
		DelegateeCandidate,
		FunctionCategory,
		SuccessResponse
	} from '$lib/types';
	import { tryCatchAsVal } from '$lib/utils';
	import { invoke } from '@tauri-apps/api/core';
	import { Loader2, LucideInfo } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';

	let { data } = $props();

	type PatientAccess = {
		patientIotaAddress: string;
		patientName: string;
		read?: AccessCapabilityData;
		write?: AccessCapabilityData;
	};

	let accesses = $state<PatientAccess[]>([]);
	let selectedPatientAddress = $state('');
	let mode = $state<DelegationMode>('read_write');
	let preset = $state<DelegationPreset>('nurse');
	let encounterDataset = $state<DatasetCategory>('RAWAT_JALAN');
	let previewReadDatasets = $state<DatasetCategory[]>([]);
	let previewWriteDatasets = $state<DatasetCategory[]>([]);
	let previewReadFunctions = $state<FunctionCategory[]>([]);
	let previewWriteFunctions = $state<FunctionCategory[]>([]);
	let delegateeCandidates = $state<DelegateeCandidate[]>([]);
	let selectedDelegateeAddress = $state('');
	let isSubmitting = $state(false);
	let visiblePatientInfo = $state<Record<string, boolean>>({});

	const DEFAULT_DELEGATION_DURATION_MS = 24 * 60 * 60 * 1000;
	const EXPIRY_SAFETY_WINDOW_MS = 1000;

	const selectedAccess = $derived(
		accesses.find((access) => access.patientIotaAddress === selectedPatientAddress)
	);
	const activeRead = $derived(selectedAccess?.read);
	const activeWrite = $derived(selectedAccess?.write);
	const selectedDelegatee = $derived(
		delegateeCandidates.find((candidate) => candidate.iotaAddress === selectedDelegateeAddress)
	);
	const availableEncounterDatasets = $derived(
		sortDatasets(
			intersect(['RAWAT_JALAN', 'RAWAT_INAP'] as DatasetCategory[], [
				...(activeRead?.readDatasets ?? []),
				...(activeWrite?.writeDatasets ?? [])
			])
		)
	);

	const groupAccesses = (capabilities: AccessCapabilitiesResponse) => {
		const map = new Map<string, PatientAccess>();
		for (const capability of capabilities.read.filter(isReadableCapability)) {
			map.set(capability.access.patientIotaAddress, {
				...(map.get(capability.access.patientIotaAddress) ?? {
					patientIotaAddress: capability.access.patientIotaAddress,
					patientName: capability.access.patientName
				}),
				read: capability
			});
		}
		for (const capability of capabilities.write.filter(isWritableCapability)) {
			map.set(capability.access.patientIotaAddress, {
				...(map.get(capability.access.patientIotaAddress) ?? {
					patientIotaAddress: capability.access.patientIotaAddress,
					patientName: capability.access.patientName
				}),
				write: capability
			});
		}
		return [...map.values()];
	};

	const shortAddress = (address: string) =>
		address.length > 18 ? `${address.slice(0, 10)}...${address.slice(-8)}` : address;

	const delegateeLabel = (candidate: DelegateeCandidate) => {
		const role = candidate.subRole ? `${candidate.role}/${candidate.subRole}` : candidate.role;
		return `${candidate.name ? `${candidate.name} - ` : ''}${role} - ${shortAddress(candidate.iotaAddress)}`;
	};

	const parseUtcExpiry = (value?: string | null) => {
		if (!value) return null;
		const normalized = /(?:Z|[+-]\d{2}:?\d{2})$/.test(value) ? value : `${value}Z`;
		const timestamp = new Date(normalized).getTime();
		return Number.isFinite(timestamp) ? timestamp : null;
	};

	const parentExpiryForMode = () => {
		const expiries: number[] = [];
		if (mode === 'read' || mode === 'read_write') {
			const readExpiry = parseUtcExpiry(activeRead?.expiresBefore);
			if (readExpiry !== null) expiries.push(readExpiry);
		}
		if (mode === 'write' || mode === 'read_write') {
			const writeExpiry = parseUtcExpiry(activeWrite?.expiresBefore);
			if (writeExpiry !== null) expiries.push(writeExpiry);
		}
		return expiries.length > 0 ? Math.min(...expiries) : null;
	};

	const delegationExpiresBefore = () => {
		const now = Date.now();
		const defaultExpiry = now + DEFAULT_DELEGATION_DURATION_MS;
		const parentExpiry = parentExpiryForMode();
		const cappedExpiry =
			parentExpiry === null
				? defaultExpiry
				: Math.min(defaultExpiry, parentExpiry - EXPIRY_SAFETY_WINDOW_MS);

		if (cappedExpiry <= now) {
			toast.error(
				'Akses parent sudah expired atau terlalu dekat kadaluarsa. Minta pasien grant access ulang.'
			);
			return null;
		}

		return new Date(cappedExpiry).toISOString();
	};

	const loadAccesses = async () => {
		const res = await tryCatchAsVal(async () => {
			return (await invoke(
				'get_current_access_capabilities'
			)) as SuccessResponse<AccessCapabilitiesResponse>;
		});
		if (!res.success) {
			toast.error(res.error);
			return [];
		}
		accesses = groupAccesses(res.data.data);
		if (!selectedPatientAddress) {
			selectedPatientAddress = data.patientAddress ?? accesses[0]?.patientIotaAddress ?? '';
		}
		applyPreset();
		return accesses;
	};

	const loadDelegateeCandidates = async () => {
		const res = await tryCatchAsVal(async () => {
			return (await invoke('get_delegatee_candidates')) as SuccessResponse<{
				candidates: DelegateeCandidate[];
			}>;
		});
		if (!res.success) {
			toast.error(res.error);
			return [];
		}
		delegateeCandidates = res.data.data.candidates;
		if (
			delegateeCandidates.length > 0 &&
			(!selectedDelegateeAddress ||
				!delegateeCandidates.some(
					(candidate) => candidate.iotaAddress === selectedDelegateeAddress
				))
		) {
			selectedDelegateeAddress = delegateeCandidates[0].iotaAddress;
		}
		return delegateeCandidates;
	};

	const loadDelegationData = async () => {
		const [loadedAccesses, loadedCandidates] = await Promise.all([
			loadAccesses(),
			loadDelegateeCandidates()
		]);
		return { loadedAccesses, loadedCandidates };
	};

	const applyPreset = () => {
		if (!selectedAccess) return;
		if (
			availableEncounterDatasets.length > 0 &&
			!availableEncounterDatasets.includes(encounterDataset)
		) {
			encounterDataset = availableEncounterDatasets[0];
		}
		const scope = presetScope({
			preset,
			encounterDataset,
			readCapability: activeRead,
			writeCapability: activeWrite
		});
		previewReadDatasets = scope.readDatasets;
		previewWriteDatasets = scope.writeDatasets;
		previewReadFunctions = scope.readFunctions;
		previewWriteFunctions = scope.writeFunctions;
	};

	const toggleDataset = (values: DatasetCategory[], value: DatasetCategory) => {
		return values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
	};

	const toggleFunction = (values: FunctionCategory[], value: FunctionCategory) => {
		return values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
	};

	const togglePatientInfo = (patientIotaAddress: string) => {
		visiblePatientInfo = {
			...visiblePatientInfo,
			[patientIotaAddress]: !visiblePatientInfo[patientIotaAddress]
		};
	};

	const submitDelegation = async () => {
		if (!selectedAccess) {
			toast.error('Pilih pasien');
			return;
		}
		if (!selectedDelegatee) {
			toast.error('Pilih personnel penerima delegasi');
			return;
		}

		if ((mode === 'read' || mode === 'read_write') && !activeRead) {
			toast.error('Read access parent tidak tersedia');
			return;
		}
		if ((mode === 'write' || mode === 'read_write') && !activeWrite) {
			toast.error('Write access parent tidak tersedia');
			return;
		}
		const source = mode === 'read' ? activeRead : activeWrite;
		if (!source) {
			toast.error('Akses parent tidak tersedia');
			return;
		}
		const sourceAccess = source.access;
		const parentEncDataPreSecretKeySeed = sourceAccess.encDataPreSecretKeySeed;
		const parentDataPreSecretKeySeedCapsule = sourceAccess.dataPreSecretKeySeedCapsule;
		if (!parentEncDataPreSecretKeySeed || !parentDataPreSecretKeySeedCapsule) {
			toast.error('Metadata kunci parent tidak lengkap. Minta pasien grant access ulang.');
			return;
		}
		if (
			(mode === 'read' || mode === 'read_write') &&
			(previewReadDatasets.length === 0 || previewReadFunctions.length === 0)
		) {
			toast.error('Scope Read tidak boleh kosong');
			return;
		}
		if (
			(mode === 'write' || mode === 'read_write') &&
			(previewWriteDatasets.length === 0 || previewWriteFunctions.length === 0)
		) {
			toast.error('Scope Write tidak boleh kosong');
			return;
		}
		const expiresBefore = delegationExpiresBefore();
		if (!expiresBefore) {
			return;
		}

		isSubmitting = true;
		const res = await tryCatchAsVal(async () => {
			return (await invoke('create_delegated_access', {
				payload: {
					mode,
					parentReadToken: activeRead?.access.accessToken ?? null,
					parentWriteToken: activeWrite?.access.accessToken ?? null,
					delegateeIotaAddress: selectedDelegatee.iotaAddress,
					delegateePrePublicKey: selectedDelegatee.prePublicKey,
					patientIotaAddress: selectedAccess.patientIotaAddress,
					patientName: selectedAccess.patientName,
					patientPrePublicKey:
						activeWrite?.access.patientPrePublicKey ??
						activeRead?.access.patientPrePublicKey ??
						null,
					parentEncDataPreSecretKeySeed,
					parentDataPreSecretKeySeedCapsule,
					expiresBefore,
					relatedRmeId:
						mode === 'read'
							? activeRead?.relatedRmeId ?? null
							: activeWrite?.relatedRmeId ?? activeRead?.relatedRmeId ?? null,
					readDatasets: mode === 'write' ? [] : previewReadDatasets,
					writeDatasets: mode === 'read' ? [] : previewWriteDatasets,
					readFunctions: mode === 'write' ? [] : previewReadFunctions,
					writeFunctions: mode === 'read' ? [] : previewWriteFunctions
				}
			})) as SuccessResponse<{ relatedRmeId?: string | null }>;
		});
		isSubmitting = false;

		if (!res.success) {
			toast.error(res.error);
			return;
		}
		toast.success('Delegasi berhasil dibuat');
	};

	$effect(() => {
		void selectedPatientAddress;
		void preset;
		void encounterDataset;
		applyPreset();
	});
</script>

<div class="flex flex-col gap-4">
	<h2 class="font-montserrat text-xl font-medium">Delegate</h2>

	{#await loadDelegationData()}
		<div class="p-4 bg-white border border-zinc-200 rounded-md flex items-center gap-2">
			<Loader2 class="animate-spin" size={18} />
			<span>Loading...</span>
		</div>
	{:then delegationData}
		<div class="bg-white border border-zinc-200 rounded-md p-4">
			<h3 class="font-medium mb-3">Hak akses saya</h3>
			{#if delegationData.loadedAccesses.length === 0}
				<p class="text-sm text-zinc-600">Belum ada akses pasien.</p>
			{:else}
				<div class="grid gap-3">
					{#each delegationData.loadedAccesses as access (access.patientIotaAddress)}
						<div class="border border-zinc-200 rounded-md p-3">
							<div class="flex items-start justify-between gap-3">
								<p class="font-medium">{access.patientName}</p>
								<button
									type="button"
									class="rounded-full p-1 text-zinc-500 transition hover:bg-zinc-100 hover:text-zinc-700"
									onclick={() => togglePatientInfo(access.patientIotaAddress)}
									aria-label={`Toggle info for ${access.patientName}`}
									aria-expanded={Boolean(visiblePatientInfo[access.patientIotaAddress])}
								>
									<LucideInfo size={16} />
								</button>
							</div>
							{#if visiblePatientInfo[access.patientIotaAddress]}
								<div class="mt-2 grid gap-1 text-sm">
									<p class="text-xs text-zinc-500 break-all">{access.patientIotaAddress}</p>
									<p>Read: {access.read ? access.read.readFunctions.length : 0} functions</p>
									<p>Write: {access.write ? access.write.writeFunctions.length : 0} functions</p>
								</div>
							{/if}
						</div>
					{/each}
				</div>
			{/if}
		</div>

		{#if delegationData.loadedAccesses.length > 0}
			<div class="bg-white border border-zinc-200 rounded-md p-4 flex flex-col gap-4">
				<label class="flex flex-col gap-1">
					<span class="text-sm font-medium">Pasien</span>
					<select class="input-text max-w-md" bind:value={selectedPatientAddress}>
						{#each delegationData.loadedAccesses as access (access.patientIotaAddress)}
							<option value={access.patientIotaAddress}>{access.patientName}</option>
						{/each}
					</select>
				</label>

				<div class="flex flex-wrap gap-2">
					{#each [{ value: 'read', label: 'Read' }, { value: 'write', label: 'Write' }, { value: 'read_write', label: 'Read + Write' }] as item}
						<button
							type="button"
							class={`px-3 py-1 rounded-md border ${mode === item.value ? 'bg-zinc-800 text-zinc-50 border-zinc-800' : 'bg-white border-zinc-200'}`}
							onclick={() => (mode = item.value as DelegationMode)}
						>
							{item.label}
						</button>
					{/each}
				</div>

				<div class="grid md:grid-cols-2 gap-3">
					<label class="flex flex-col gap-1">
						<span class="text-sm font-medium">Preset</span>
						<select class="input-text" bind:value={preset}>
							{#each presetItems as item (item.value)}
								<option value={item.value}>{item.label}</option>
							{/each}
						</select>
					</label>
					<label class="flex flex-col gap-1">
						<span class="text-sm font-medium">Encounter dataset</span>
						<select class="input-text" bind:value={encounterDataset}>
							{#each availableEncounterDatasets as dataset (dataset)}
								<option value={dataset}>{datasetLabels[dataset]}</option>
							{/each}
						</select>
					</label>
				</div>

				<div class="grid md:grid-cols-2 gap-4">
					<div class="border border-zinc-200 rounded-md p-3">
						<p class="font-medium mb-2">Read preview</p>
						{#each sortDatasets(activeRead?.readDatasets ?? []) as dataset (dataset)}
							<label class="flex items-center gap-2 text-sm">
								<input
									type="checkbox"
									checked={previewReadDatasets.includes(dataset)}
									onchange={() =>
										(previewReadDatasets = toggleDataset(previewReadDatasets, dataset))}
								/>
								{datasetLabels[dataset]}
							</label>
						{/each}
						<div class="mt-3 grid gap-1">
							{#each sortFunctions(activeRead?.readFunctions ?? []) as functionCategory (functionCategory)}
								<label class="flex items-center gap-2 text-sm">
									<input
										type="checkbox"
										checked={previewReadFunctions.includes(functionCategory)}
										onchange={() =>
											(previewReadFunctions = toggleFunction(
												previewReadFunctions,
												functionCategory
											))}
									/>
									{functionLabels[functionCategory]}
								</label>
							{/each}
						</div>
					</div>

					<div class="border border-zinc-200 rounded-md p-3">
						<p class="font-medium mb-2">Write preview</p>
						{#each sortDatasets(activeWrite?.writeDatasets ?? []) as dataset (dataset)}
							<label class="flex items-center gap-2 text-sm">
								<input
									type="checkbox"
									checked={previewWriteDatasets.includes(dataset)}
									onchange={() =>
										(previewWriteDatasets = toggleDataset(previewWriteDatasets, dataset))}
								/>
								{datasetLabels[dataset]}
							</label>
						{/each}
						<div class="mt-3 grid gap-1">
							{#each sortFunctions(activeWrite?.writeFunctions ?? []) as functionCategory (functionCategory)}
								<label class="flex items-center gap-2 text-sm">
									<input
										type="checkbox"
										checked={previewWriteFunctions.includes(functionCategory)}
										onchange={() =>
											(previewWriteFunctions = toggleFunction(
												previewWriteFunctions,
												functionCategory
											))}
									/>
									{functionLabels[functionCategory]}
								</label>
							{/each}
						</div>
					</div>
				</div>

				<label class="flex flex-col gap-1">
					<span class="text-sm font-medium">Delegatee</span>
					{#if delegationData.loadedCandidates.length === 0}
						<p class="text-sm text-zinc-600">
							Belum ada personnel aktif dengan public key delegasi di rumah sakit ini.
						</p>
					{:else}
						<select class="input-text max-w-xl" bind:value={selectedDelegateeAddress}>
							{#each delegationData.loadedCandidates as candidate (candidate.iotaAddress)}
								<option value={candidate.iotaAddress}>{delegateeLabel(candidate)}</option>
							{/each}
						</select>
					{/if}
				</label>

				<button
					type="button"
					class="button-dark max-w-max px-4 disabled:opacity-50"
					disabled={isSubmitting || delegationData.loadedCandidates.length === 0}
					onclick={submitDelegation}
				>
					{isSubmitting ? 'Delegating...' : 'Delegate'}
				</button>
			</div>
		{/if}
	{/await}
</div>
