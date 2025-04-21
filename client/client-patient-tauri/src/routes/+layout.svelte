<script lang="ts">
	import '../app.css';
	import '@fontsource-variable/inter';
	import '@fontsource-variable/montserrat';

	let { children } = $props();
</script>

<main class="flex flex-1 min-h-svh w-full flex-col overflow-auto">
	<div class="h-14 px-4 flex items-center border-b border-zinc-200">
		<h2 class="text-lg font-bold font-montserrat">DecMed</h2>
	</div>
	<div class="flex flex-col w-full p-4 overflow-auto h-[calc(100vh-3.5rem)]">
		{@render children()}
	</div>
</main>
