<script lang="ts">
	import { JPEG_MIME_TYPE, PNG_MIME_TYPE } from '$lib/constants.js';
	import { hospitalQrSchema } from '$lib/schema.js';
	import { Loader } from '@lucide/svelte';
	import { invoke } from '@tauri-apps/api/core';
	import { fileProxy, superForm } from 'sveltekit-superforms';
	import { zodClient } from 'sveltekit-superforms/adapters';

	let { data } = $props();

	const {
		form: hospitalQrForm,
		enhance: hospitalQrFormEnhance,
		errors: hospitalQrFormErrors,
		constraints: hospitalQrFormConstraints,
		delayed: hospitalQrFormDelayed
	} = superForm(data.hospitalQrForm, {
		SPA: true,
		validators: zodClient(hospitalQrSchema),
		delayMs: 100,
		onUpdate: async ({ form, result }) => {
			if (result.type === 'success') {
				let qrBytes = await form.data.qr.bytes();
				invoke('process_qr', { qrBytes });
			}
		}
	});
	const qrFileProxy = fileProxy(hospitalQrForm, 'qr');
</script>

<div class="flex flex-col">
	<h2 class="font-montserrat font-medium text-xl my-2">Scan Hospital QR</h2>
	<div class="bg-zinc-100 border border-zinc-200 rounded-md h-56 flex items-center justify-center">
		<p>Scan Placeholder</p>
	</div>
	<form
		method="post"
		class="flex flex-col gap-2 my-4"
		enctype="multipart/form-data"
		use:hospitalQrFormEnhance
		{...$hospitalQrFormConstraints.qr}
	>
		<label for="qr" class="font-medium">Input QR</label>
		<input
			id="qr"
			name="qr"
			type="file"
			class="border border-zinc-200 p-4 bg-zinc-100 placeholder-cyan-950 rounded-md"
			accept={`${PNG_MIME_TYPE}, ${JPEG_MIME_TYPE}`}
			bind:files={$qrFileProxy}
		/>
		{#if $hospitalQrFormErrors.qr}
			<span class="px-2 py-1 border-t border-zinc-200 text-xs font-medium text-red-500 bg-red-50"
				>{$hospitalQrFormErrors.qr[0]}</span
			>
		{/if}
		<button
			type="submit"
			class="button-dark disabled:bg-zinc-700"
			disabled={$hospitalQrFormDelayed}
		>
			{#if $hospitalQrFormDelayed}
				<Loader class="animate-spin" />
			{:else}
				Submit
			{/if}
		</button>
	</form>
</div>
