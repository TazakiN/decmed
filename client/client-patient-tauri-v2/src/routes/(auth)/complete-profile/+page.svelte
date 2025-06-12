<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { completeProfileSchema } from '$lib/schema';
	import type { SuccessResponse } from '$lib/types.js';
	import { cn, tryCatchAsVal, waitMs } from '$lib/utils';
	import { Loader2 } from '@lucide/svelte';
	import { invoke } from '@tauri-apps/api/core';
	import { Label } from 'bits-ui';
	import { toast } from 'svelte-sonner';
	import { superForm } from 'sveltekit-superforms';
	import { zodClient } from 'sveltekit-superforms/adapters';

	let { data } = $props();

	const {
		form: completeProfileForm,
		enhance: completeProfileFormEnhance,
		constraints: completeProfileFormConstraints,
		errors: completeProfileFormErrors,
		delayed: completeProfileFormDelayed
	} = superForm(data.completeProfileForm, {
		delayMs: 100,
		validators: zodClient(completeProfileSchema),
		dataType: 'json',
		SPA: true,
		onUpdate: async ({ result, form, cancel }) => {
			if (result.type === 'success') {
				const resultInvokeUpdateProfile = await tryCatchAsVal(async () => {
					return (await invoke('update_profile', {
						data: {
							name: form.data.name
						}
					})) as SuccessResponse<null>;
				});

				if (!resultInvokeUpdateProfile.success) {
					cancel();
					toast.error(resultInvokeUpdateProfile.error);
					return;
				}

				// wait for 2 seconds for transaction be submitted
				await waitMs(2 * 1000);

				toast.success('Profile updated successfully');
			}
		}
	});
</script>

<div class="flex flex-col max-w-md w-full flex-1 items-center justify-center p-4">
	<h2 class="font-montserrat text-xl font-medium my-4">Complete Your Profile</h2>
	<form
		method="post"
		class="flex flex-col gap-2 bg-zinc-50 border border-zinc-200 rounded-md p-2 w-full"
		use:completeProfileFormEnhance
	>
		<div
			class={cn(
				'flex flex-col w-full border border-zinc-200',
				$completeProfileFormErrors.name && 'border-red-200'
			)}
		>
			<Label.Root
				for="name"
				class="font-medium text-sm after:content-['*'] after:text-red-500 p-2 border-b border-zinc-200"
				>Name</Label.Root
			>
			<input
				type="text"
				id="name"
				name="name"
				class="p-2 outline-0 bg-white"
				placeholder="xxx-xxxxxxxx"
				bind:value={$completeProfileForm.name}
				{...$completeProfileFormConstraints.name}
			/>
			{#if $completeProfileFormErrors.name}
				<span class="px-2 py-1 border-t border-zinc-200 text-xs font-medium text-red-500 bg-red-50"
					>{$completeProfileFormErrors.name[0]}</span
				>
			{/if}
		</div>
		<button type="submit" class="button-dark mt-2 flex items-center justify-center">
			{#if $completeProfileFormDelayed}
				<Loader2 class="animate-spin" />
			{:else}
				Continue
			{/if}
		</button>
	</form>
</div>
