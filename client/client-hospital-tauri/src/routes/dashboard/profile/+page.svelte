<script lang="ts">
	import { getAuthContext } from '../../(context)/auth-context.svelte';

	const authContext = getAuthContext();
</script>

Profile of {authContext.role}
