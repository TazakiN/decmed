<script lang="ts">
	import Select from '$lib/components/select.svelte';
	import { EmrCreateState } from './state.svelte.js';

	let { data } = $props();

	const emrCreateState = new EmrCreateState({
		accessToken: data.accessToken,
		patientIotaAddress: data.patientIotaAddress,
		patientPrePublicKey: data.patientPrePublicKey,
		createMedicalRecordForm: data.createMedicalRecordForm
	});
	const {
		form: createMedicalRecordForm,
		enhance: createMedicalRecordFormEnhance,
		errors: createMedicalRecordFormErrors
	} = emrCreateState.createMedicalRecordFormMeta;
</script>

Create EMR of {data.patientIotaAddress}

<form
	method="post"
	class="flex flex-col p-4 bg-white border border-zinc-200 rounded-md my-4 gap-2"
	use:createMedicalRecordFormEnhance
>
	<div class="flex flex-col gap-1">
		<label for="">Category</label>
		<Select
			items={emrCreateState.medicalDataMainCategory}
			bind:value={$createMedicalRecordForm.mainCategory}
			type="single"
		/>
		{#if $createMedicalRecordFormErrors.mainCategory}
			<span class="px-2 py-1 text-xs font-medium text-red-500 bg-red-50"
				>{$createMedicalRecordFormErrors.mainCategory[0]}</span
			>
		{/if}
	</div>
	<div class="flex flex-col gap-1">
		<label for="">Sub Category</label>
		<Select
			items={emrCreateState.medicalDataSubCategory}
			bind:value={$createMedicalRecordForm.subCategory}
			type="single"
		/>
		{#if $createMedicalRecordFormErrors.subCategory}
			<span class="px-2 py-1 text-xs font-medium text-red-500 bg-red-50"
				>{$createMedicalRecordFormErrors.subCategory[0]}</span
			>
		{/if}
	</div>

	<button
		class="bg-zinc-800 px-4 py-2 rounded-md text-zinc-50 max-w-max mt-2 cursor-pointer"
		type="submit">Create</button
	>
</form>
