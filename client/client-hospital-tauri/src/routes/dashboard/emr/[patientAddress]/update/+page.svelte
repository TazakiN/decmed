<script lang="ts">
	import Error from '$lib/components/error.svelte';
	import Select from '$lib/components/select.svelte';
	import { EmrUpdateState } from './state.svelte.js';

	let { data } = $props();

	const emrUpdateState = new EmrUpdateState({
		accessToken: data.accessToken,
		index: data.medicalMetadataIndex,
		patientIotaAddress: data.patientIotaAddress,
		patientPrePublicKey: data.patientPrePublicKey,
		updateMedicalRecordForm: data.updateMedicalRecordForm
	});

	const {
		form: updateMedicalRecordForm,
		enhance: updateMedicalRecordFormEnhance,
		errors: updateMedicalRecordFormErrors
	} = emrUpdateState.updateMedicalRecordFormMeta;
</script>

Update EMR of {data.patientIotaAddress}

{#await emrUpdateState.fetchMedicalRecord}
	Loading..
{:then record}
	<form
		method="post"
		class="flex flex-col p-4 bg-white border border-zinc-200 rounded-md my-4 gap-2"
		use:updateMedicalRecordFormEnhance
	>
		<div class="flex flex-col gap-1">
			<label for="">Category</label>
			<Select
				items={emrUpdateState.medicalDataMainCategory}
				bind:value={$updateMedicalRecordForm.mainCategory}
				type="single"
			/>
			{#if $updateMedicalRecordFormErrors.mainCategory}
				<span class="px-2 py-1 text-xs font-medium text-red-500 bg-red-50"
					>{$updateMedicalRecordFormErrors.mainCategory[0]}</span
				>
			{/if}
		</div>
		<div class="flex flex-col gap-1">
			<label for="">Sub Category</label>
			<Select
				items={emrUpdateState.medicalDataSubCategory}
				bind:value={$updateMedicalRecordForm.subCategory}
				type="single"
			/>
			{#if $updateMedicalRecordFormErrors.subCategory}
				<span class="px-2 py-1 text-xs font-medium text-red-500 bg-red-50"
					>{$updateMedicalRecordFormErrors.subCategory[0]}</span
				>
			{/if}
		</div>

		<button
			class="bg-zinc-800 px-4 py-2 rounded-md text-zinc-50 max-w-max mt-2 cursor-pointer"
			type="submit">Update</button
		>
	</form>
{:catch e}
	{#if e === '404'}
		<div class="bg-white p-4 border border-zinc-200 rounded-md my-4">
			<p>No medical record found</p>
		</div>
	{:else}
		<Error error={e} />
	{/if}
	<a
		href={`/dashboard/emr/${data.patientIotaAddress}/create?accessToken=${data.accessToken}&patientPrePublicKey=${data.patientPrePublicKey}`}
		class="bg-zinc-800 text-zinc-50 border border-zinc-200 px-4 py-2 rounded-md max-w-max"
		>Create medical record</a
	>
{/await}
