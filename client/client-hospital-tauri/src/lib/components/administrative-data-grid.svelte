<script lang="ts">
	import type { TauriPatientPrivateAdministrativeData } from '$lib/types';

	let { data }: { data: TauriPatientPrivateAdministrativeData } = $props();
</script>

<h3 class="font-medium text-md my-4">Administrative Data</h3>
<div class="grid grid-cols-[150px_1fr] items-center mb-4">
	<div class="p-2 bg-white border border-b-0 border-zinc-200">
		<span>NIK</span>
	</div>
	<div class="p-2 border border-zinc-200 border-b-0 border-l-0">
		<span>{data.id}</span>
	</div>
	<div class="p-2 bg-white border border-b-0 border-zinc-200">
		<span>Name</span>
	</div>
	<div class="p-2 border border-zinc-200 border-b-0 border-l-0">
		<span>{data.name ?? '—'}</span>
	</div>
	<div class="p-2 bg-white border border-b-0 border-zinc-200">
		<span>Birth Place</span>
	</div>
	<div class="p-2 border border-zinc-200 border-b-0 border-l-0">
		<span>{data.birth_place ?? '—'}</span>
	</div>
	<div class="p-2 bg-white border border-b-0 border-zinc-200">
		<span>Date of Birth</span>
	</div>
	<div class="p-2 border border-zinc-200 border-b-0 border-l-0">
		<span>{data.date_of_birth ?? '—'}</span>
	</div>
	<div class="p-2 bg-white border border-b-0 border-zinc-200">
		<span>Gender</span>
	</div>
	<div class="p-2 border border-zinc-200 border-b-0 border-l-0">
		<span>{data.gender ?? '—'}</span>
	</div>
	<div class="p-2 bg-white border border-b-0 border-zinc-200">
		<span>Religion</span>
	</div>
	<div class="p-2 border border-zinc-200 border-b-0 border-l-0">
		<span>{data.religion ?? '—'}</span>
	</div>
	<div class="p-2 bg-white border border-b-0 border-zinc-200">
		<span>Education</span>
	</div>
	<div class="p-2 border border-zinc-200 border-b-0 border-l-0">
		<span>{data.education ?? '—'}</span>
	</div>
	<div class="p-2 bg-white border border-b-0 border-zinc-200">
		<span>Occupation</span>
	</div>
	<div class="p-2 border border-zinc-200 border-b-0 border-l-0">
		<span>{data.occupation ?? '—'}</span>
	</div>
	<div class="p-2 bg-white border border-zinc-200">
		<span>Marital Status</span>
	</div>
	<div class="p-2 border border-zinc-200 border-l-0">
		<span>{data.marital_status ?? '—'}</span>
	</div>
</div>
