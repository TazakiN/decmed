<script lang="ts">
	let { children } = $props();
</script>

<div class="flex flex-col p-4 items-center justify-center w-full flex-1">
	{@render children()}
</div>
