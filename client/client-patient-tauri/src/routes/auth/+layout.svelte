<script lang="ts">
  let { children } = $props();
</script>

<div class="flex-1 flex-col items-center justify-center flex">
  {@render children()}
</div>
