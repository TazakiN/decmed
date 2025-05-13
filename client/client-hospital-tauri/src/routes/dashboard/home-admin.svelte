<script lang="ts">
	import Dialog from '$lib/components/dialog.svelte';
	import type { Account } from '$lib/types';
	import { invoke } from '@tauri-apps/api/core';

	const accounts: Account[] = [
		{
			id: 'ADM-111111',
			name: 'Administrative 1',
			role: 'administrative'
		},
		{
			id: 'ADM-222222',
			name: 'Administrative 2',
			role: 'administrative'
		},
		{
			id: 'MED-111111',
			name: 'Doctor 1',
			role: 'medical'
		},
		{
			id: 'MED-222222',
			name: 'Nurse 1',
			role: 'medical'
		}
	];

	async function test() {
		await invoke('is_activation_key_used');
	}
</script>

<div class="flex flex-col w-full flex-1">
	<div class="flex items-center justify-between">
		<h2 class="font-medium">Accounts</h2>
		<Dialog buttonText="+ Account">
			{#snippet title()}
				Add New Account
			{/snippet}
			<form action="" method="POST" class="flex flex-col gap-2 mt-4">
				<label for="id" class="font-medium">ID</label>
				<input id="id" name="id" type="text" class="input-text" placeholder="Enter ID" />
				<button class="button-dark">Add Account</button>
			</form>
		</Dialog>
	</div>
	<div class="flex flex-col my-4 bg-white">
		{#each accounts as account (account.id)}
			<div class="flex flex-col p-2 border [&:not(:last-child)]:border-b-0 w-full border-zinc-200">
				<div class="flex items-center justify-between gap-2">
					<p class="text-zinc-400 text-sm">{account.id}</p>
					<p class="px-2 py-0.5 border border-zinc-200 bg-zinc-50 text-xs rounded-lg text-zinc-400">
						{account.role}
					</p>
				</div>
				<p>{account.name}</p>
			</div>
		{/each}
	</div>
	<button onclick={test}>test</button>
</div>
