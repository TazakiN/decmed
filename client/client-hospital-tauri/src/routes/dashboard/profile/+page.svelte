<script lang="ts">
	import QRCode from 'qrcode';
	import { create, BaseDirectory, mkdir, exists } from '@tauri-apps/plugin-fs';
	import { toast } from 'svelte-sonner';

	let { data } = $props();
	let qr = $state('');
	let qrFileName = $state(`qr-${data.admData?.id ?? 'unknown'}`);

	QRCode.toString(
		data.admData?.idHash ?? '',
		{
			type: 'svg'
		},
		function (err, string) {
			if (err) throw err;
			qr = string;
		}
	);

	const downloadQr = async () => {
		if (
			!(await exists('decmed-hospital/', {
				baseDir: BaseDirectory.Home
			}))
		) {
			await mkdir('decmed-hospital', {
				baseDir: BaseDirectory.Home
			});
		}

		const res = await QRCode.toDataURL(data.admData?.idHash ?? '', {
			type: 'image/png'
		});
		const response = await fetch(res);
		const arrayBuffer = await response.arrayBuffer();
		const buff = new Uint8Array(arrayBuffer);

		const file = await create(`decmed-hospital/${qrFileName}.png`, {
			baseDir: BaseDirectory.Home
		});
		await file.write(buff);
		await file.close();

		toast.success(`QR Code downloaded to ~/decmed-hospital/${qrFileName}.png`);
	};
</script>

<h2 class="font-medium text-xl font-montserrat mb-2">Profile</h2>
<div class="p-3 rounded-md bg-zinc-100 border border-zinc-200">
	<div class="grid grid-cols-[100px_1fr] gap-2 max-w-full items-center">
		<p>Id:</p>
		<p class="bg-white border border-zinc-200 px-2 py-1 truncate rounded-md text-sm">
			{data.admData?.id}
		</p>
		<!-- <p class="break-all line-clamp-1">Id Hash:</p>
		<p class="bg-white border border-zinc-200 px-2 py-1 truncate rounded-md text-sm">
			{data.admData?.idHash}
		</p> -->
		<p class="break-all">Name:</p>
		<p class="bg-white border border-zinc-200 px-2 py-1 truncate rounded-md text-sm">
			{data.admData?.name}
		</p>
		<p class="break-all">Hospital:</p>
		<p class="bg-white border border-zinc-200 px-2 py-1 truncate rounded-md text-sm">
			{data.admData?.hospital}
		</p>
	</div>
</div>

<div class="w-full flex items-center justify-center flex-col">
	<div class="max-w-80 w-full my-2 border border-zinc-200">
		{@html qr}
	</div>
	<button class="button-dark max-w-sm" onclick={downloadQr}>Download QR Code</button>
</div>
