<script lang="ts">
  import "../app.css";
  let { children } = $props();
</script>

<main class="flex flex-1 min-h-svh w-full flex-col p-2">
  {@render children()}
</main>
