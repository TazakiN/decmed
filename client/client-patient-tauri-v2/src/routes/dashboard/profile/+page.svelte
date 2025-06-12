<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { copyToClipboard } from '$lib/utils.js';
	import { Copy } from '@lucide/svelte';
	import { invoke } from '@tauri-apps/api/core';

	let { data } = $props();

	async function signout() {
		await invoke('signout');
		invalidateAll();
	}

	async function getPrePubKey() {
		await invoke('get_pre_public_key_bytes');
	}
</script>

<h2 class="font-montserrat font-medium text-xl my-2">Profile Page</h2>
<div class="p-3 rounded-md bg-zinc-100 border border-zinc-200 my-4">
	<div class="grid grid-cols-[100px_1fr_20px] max-w-full items-center gap-2">
		<p>NIK:</p>
		<p class="bg-white px-2 py-1 rounded-md border border-zinc-200 truncate text-sm">
			{data.profile?.id}
		</p>
		<button
			class="flex items-center justify-center cursor-pointer"
			onclick={() => copyToClipboard(data.profile?.id || '')}><Copy size={16} /></button
		>
		<p class="break-all">NIK Hash:</p>
		<p class="bg-white px-2 py-1 rounded-md border border-zinc-200 truncate text-sm">
			{data.profile?.idHash}
		</p>
		<button
			class="flex items-center justify-center cursor-pointer"
			onclick={() => copyToClipboard(data.profile?.idHash || '')}><Copy size={16} /></button
		>
		<p class="break-all">Name:</p>
		<p class="bg-white px-2 py-1 rounded-md border border-zinc-200 truncate text-sm">
			{data.profile?.name}
		</p>
		<button
			class="flex items-center justify-center cursor-pointer"
			onclick={() => copyToClipboard(data.profile?.name || '')}><Copy size={16} /></button
		>
	</div>
</div>

<button onclick={signout} class="button-dark my-2">Sign Out</button>
<button onclick={getPrePubKey} class="button-dark my-2">Get PRE Pub Key</button>
