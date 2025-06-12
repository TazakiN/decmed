<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { getAuthContext } from '../(context)/auth-context.svelte';
	import HomeAdmin from './home-admin.svelte';
	import HomeAdministrative from './home-administrative.svelte';
	import HomeMedical from './home-medical.svelte';
	import {
		ADMIN_ROLE,
		ADMINISTRATIVE_PERSONNEL_ROLE,
		MEDICAL_PERSONNEL_ROLE
	} from '$lib/constants';
	import { invalidateAll } from '$app/navigation';
	import { tryCatchAsVal } from '$lib/utils';
	import type { SuccessResponse } from '$lib/types';
	import { toast } from 'svelte-sonner';

	let { data } = $props();

	const authContext = getAuthContext();
	authContext.role = data.role;

	async function signout() {
		const resInvokeSignout = await tryCatchAsVal(async () => {
			return (await invoke('signout')) as SuccessResponse<null>;
		});

		if (!resInvokeSignout.success) {
			toast.error('Signout failed');
			return;
		}

		authContext.role = undefined;
		invalidateAll();
	}
</script>

{#if data.role === ADMIN_ROLE}
	<HomeAdmin addPersonnelFormData={data.addPersonnelForm!} personnels={data.personnels} />
{:else if data.role === MEDICAL_PERSONNEL_ROLE}
	<HomeMedical />
{:else if data.role === ADMINISTRATIVE_PERSONNEL_ROLE}
	<HomeAdministrative />
{/if}

<button class="btn-dark" onclick={signout}>Signout</button>
