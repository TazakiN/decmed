<script lang="ts">
	import type { SuccessResponse, TauriMedicalData } from '$lib/types.js';
	import { tryCatchAsVal } from '$lib/utils.js';
	import { Loader2, LucideArrowLeft } from '@lucide/svelte';
	import { invoke } from '@tauri-apps/api/core';
	import { toast } from 'svelte-sonner';

	let { data } = $props();

	let fetchMedicalRecord = $state(getMedicalRecord());

	async function getMedicalRecord() {
		const resInvokeGetMedicalRecord = await tryCatchAsVal(async () => {
			return (await invoke('get_medical_record', {
				index: data.emrIndex
			})) as SuccessResponse<TauriMedicalData>;
		});

		if (!resInvokeGetMedicalRecord.success) {
			toast.error(resInvokeGetMedicalRecord.error);
			throw new Error(resInvokeGetMedicalRecord.error);
		}

		return resInvokeGetMedicalRecord.data.data;
	}
</script>

<div class="mb-4 mt-2">
	<a href="/dashboard" class="flex max-w-max items-center gap-1"
		><LucideArrowLeft size={18} />Back</a
	>
</div>

{#await fetchMedicalRecord}
	<div class="h-20 animate-pulse bg-zinc-100 w-full flex items-center justify-center">
		<Loader2 class="animate-spin" />
	</div>
{:then record}
	<div class="flex flex-col gap-2">
		<div class="bg-zinc-50 rounded-md border border-zinc-200 p-2 flex flex-col gap-3">
			<div class="flex flex-col">
				<p class="text-xs font-medium text-zinc-600">Index</p>
				<p>{data.emrIndex}</p>
			</div>
			<div class="flex flex-col">
				<p class="text-xs font-medium text-zinc-600">Main Category</p>
				<p>{record.main_category}</p>
			</div>
			<div class="flex flex-col">
				<p class="text-xs font-medium text-zinc-600">Sub Category</p>
				<p>{record.sub_category}</p>
			</div>
		</div>
	</div>
{:catch e}
	<p>Something went wrong.</p>
	{JSON.stringify(e)}
{/await}
