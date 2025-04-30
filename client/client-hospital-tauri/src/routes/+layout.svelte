<script lang="ts">
	import '../app.css';
	import '@fontsource-variable/inter';
	import '@fontsource-variable/montserrat';

	let { children } = $props();
</script>

<main class="flex flex-col w-full flex-1 min-h-svh">
	{@render children()}
</main>
