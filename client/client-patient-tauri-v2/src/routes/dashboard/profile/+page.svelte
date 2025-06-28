<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import type { SuccessResponse, TauriAdministrativeData } from '$lib/types.js';
	import { copyToClipboard, tryCatchAsVal } from '$lib/utils.js';
	import { Copy, Loader2 } from '@lucide/svelte';
	import { invoke } from '@tauri-apps/api/core';
	import { toast } from 'svelte-sonner';

	let fetchProfile = $state(getProfile());

	async function signout() {
		await invoke('signout');
		invalidateAll();
	}

	async function getProfile() {
		const resInvokeGetProfile = await tryCatchAsVal(async () => {
			return (await invoke('get_profile')) as SuccessResponse<TauriAdministrativeData>;
		});

		if (!resInvokeGetProfile.success) {
			toast.error(resInvokeGetProfile.error);
			throw new Error(resInvokeGetProfile.error);
		}

		return resInvokeGetProfile.data.data;
	}
</script>

<h2 class="font-montserrat font-medium text-xl my-2">Profile Page</h2>
{#await fetchProfile}
	<div class="h-20 animate-pulse bg-zinc-100 w-full flex items-center justify-center">
		<Loader2 class="animate-spin" />
	</div>
{:then profile}
	<div class="p-3 rounded-md bg-zinc-100 border border-zinc-200 my-4">
		<div class="grid grid-cols-[100px_1fr_20px] max-w-full items-center gap-2">
			<p>NIK:</p>
			<p class="bg-white px-2 py-1 rounded-md border border-zinc-200 truncate text-sm">
				{profile.id}
			</p>
			<button
				class="flex items-center justify-center cursor-pointer"
				onclick={() => copyToClipboard(profile.id || '')}><Copy size={16} /></button
			>
			<p class="break-all">NIK Hash:</p>
			<p class="bg-white px-2 py-1 rounded-md border border-zinc-200 truncate text-sm">
				{profile.idHash}
			</p>
			<button
				class="flex items-center justify-center cursor-pointer"
				onclick={() => copyToClipboard(profile.idHash || '')}><Copy size={16} /></button
			>
			<p class="break-all">Name:</p>
			<p class="bg-white px-2 py-1 rounded-md border border-zinc-200 truncate text-sm">
				{profile.name}
			</p>
			<button
				class="flex items-center justify-center cursor-pointer"
				onclick={() => copyToClipboard(profile.name || '')}><Copy size={16} /></button
			>
			<p class="break-all">IOTA Address:</p>
			<p class="bg-white px-2 py-1 rounded-md border border-zinc-200 truncate text-sm">
				{profile.iotaAddress}
			</p>
			<button
				class="flex items-center justify-center cursor-pointer"
				onclick={() => copyToClipboard(profile.iotaAddress || '')}><Copy size={16} /></button
			>
			<p class="break-all">PRE Public Key:</p>
			<p class="bg-white px-2 py-1 rounded-md border border-zinc-200 truncate text-sm">
				{profile.prePublicKey}
			</p>
			<button
				class="flex items-center justify-center cursor-pointer"
				onclick={() => copyToClipboard(profile.prePublicKey || '')}><Copy size={16} /></button
			>
		</div>
	</div>
{:catch e}
	<p>Something went wrong.</p>
	{JSON.stringify(e)}
{/await}

<button onclick={signout} class="button-dark my-2">Sign Out</button>
