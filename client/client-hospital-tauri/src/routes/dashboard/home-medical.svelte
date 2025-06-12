<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { toast } from 'svelte-sonner';

	async function addTempMedicalRecord() {
		try {
			await invoke('new_medical_record', {
				patientId: '1414141414141414',
				patientPrePublicKey: [
					3, 100, 188, 43, 73, 50, 2, 13, 238, 15, 188, 123, 29, 252, 194, 47, 52, 19, 140, 194, 87,
					214, 41, 165, 245, 217, 200, 78, 93, 84, 88, 69, 170
				],
				pin: '123456'
			});
			toast.success('Success');
		} catch (err) {
			console.log(err);
			if (err instanceof Error) {
				toast.error(err.message);
			}
		}
	}
</script>

<button class="button-dark" onclick={addTempMedicalRecord}>Add Temp Medical Record</button>
