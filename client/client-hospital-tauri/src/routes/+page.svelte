<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';

	let password = $state<string>('undefined');

	async function getPassword() {
		password = await invoke('get_password_from_keyring');
	}
</script>

<p>Hompage</p>

{password}

<div class="flex flex-col gap-2">
	<button class="border p-2" onclick={() => console.log('here')}>click fe</button>
	<button class="border p-2" onclick={() => invoke('greet', { name: 'test' })}>click be</button>
	<button class="border p-2" onclick={getPassword}>get password</button>
</div>
