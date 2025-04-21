<script lang="ts">
	import { cn } from '$lib/utils';
	import { DeleteIcon, TriangleAlertIcon } from '@lucide/svelte';
	import { invoke } from '@tauri-apps/api/core';

	type SignUpError = {
		[key: number]: string;
	};

	const STAGE_COUNT = 5;

	let current_stage = $state<number>(0);
	let mnemonic = $state<string | null>('osme random jiwoo jiwwo jiwwo jiwwo jiwwoo jiwoo jiwooo ');
	let confirmMnemonic = $state<string | null>(null);
	let errors = $state<SignUpError>({});
	let pin = $state<number[]>([]);
	let confirmPin = $state<number[]>([]);
	let nik = $state<string | null>(null);

	const next_actions = {
		1: {
			label: 'Lanjut',
			action: () => {
				current_stage = 2;
			}
		},
		2: {
			label: 'Lanjut',
			action: () => {
				if (mnemonic?.trim() === confirmMnemonic?.trim()) {
					current_stage = 3;
				} else {
					errors[2] = 'Kata seed tidak cocok';
				}
			}
		},
		3: {
			label: 'Lanjut',
			action: async () => {
				if (pin.length === 6) {
					const res = await invoke('check_pin', { pin });
					if (!res) {
						errors[3] = 'PIN tidak valid';
					}
					current_stage = 4;
				}
			}
		},
		4: {
			label: 'Lanjut',
			action: async () => {
				if (pin.join('') === confirmPin.join('')) {
					const res = await invoke('check_confirm_pin', { confirmPin });
					if (!res) {
						errors[4] = 'PIN tidak cocok';
					}
					current_stage = 5;
				} else {
					errors[4] = 'PIN tidak cocok';
				}
			}
		},
		5: {
			label: 'Submit',
			action: async () => {
				const resCheckNik = await invoke('check_nik', { nik });
				if (!resCheckNik) {
					errors[5] = 'NIK tidak valid';
				}
				const res = await invoke('register_patient');
				console.log(res);
			}
		}
	};

	async function startRegistration() {
		current_stage = 1;

		mnemonic = await invoke('generate_mnemonic');
	}

	function enterPin(digit: number) {
		if (pin.length < 6) {
			pin.push(digit);
		}
	}

	function backspacePin() {
		pin.pop();
	}

	function reenterPin(digit: number) {
		if (confirmPin.length < 6) {
			confirmPin.push(digit);
		}
	}

	function backspaceConfirmPin() {
		confirmPin.pop();
		if (errors[4]) {
			delete errors[4];
		}
	}
</script>

<div class="w-full flex-1 flex-col flex">
	{#if current_stage === 0}
		<div class="flex-1 flex items-center justify-center flex-col gap-4">
			<button class="button" onclick={startRegistration}>Mulai Registrasi</button>
			<p class="text-sm">
				Sudah punya akun?
				<a href="/auth/signin" class="text-zinc-500 underline underline-offset-4">Masuk</a>
			</p>
		</div>
	{/if}
	{#if current_stage > 0}
		<div class="flex flex-col justify-between flex-1">
			<span class="font-medium bg-blue-100 border border-blue-300 max-w-max rounded-md px-2"
				>Registrasi</span
			>
			<div class="flex items-center w-full justify-center my-4">
				{#each new Array(STAGE_COUNT) as _, i}
					<div
						class={cn(
							'rounded-full border border-zinc-200 size-10 flex items-center justify-center font-medium z-10',
							i < current_stage && 'bg-zinc-100',
							i === current_stage - 1 && 'ring-2 ring-zinc-400'
						)}
					>
						{i + 1}
					</div>
					{#if i < STAGE_COUNT - 1}
						<div class="border-b flex-1 w-full flex shrink-0 border z-0 border-zinc-200"></div>
					{/if}
				{/each}
			</div>
			<div class="flex-1 flex items-center justify-center flex-col gap-4">
				{#if current_stage === 1}
					<div class="flex flex-col">
						<div
							class="flex items-center justify-center w-full p-2 border border-zinc-200 rounded-t-md"
						>
							<p class="font-medium text-center">
								{mnemonic}
							</p>
						</div>
						<div
							class="p-2 border border-t-0 border-zinc-200 rounded-b-md bg-amber-100 flex items-start gap-2"
						>
							<span class="shrink-0">
								<TriangleAlertIcon strokeWidth={1} />
							</span>
							<p class="text-sm">
								Pastikan Anda menyimpan <span class="font-bold">12 kata seed</span> di atas dengan
								aman dan urutan yang sama. 12 kata tersebut akan digunakan untuk masuk ke akun Anda
								dan jika hilang
								<span class="font-bold">tidak dapat diganti maupun dikembalikan!</span>
							</p>
						</div>
					</div>
				{/if}
				{#if current_stage === 2}
					<p>Silakan masukkan kembali 12 kata seed yang Anda peroleh sebelumnya.</p>
					<textarea
						class={cn('input-text', errors[2] && 'bg-red-100 ring-2 ring-red-300')}
						placeholder="jiwoo jiwoo jiwoo jiwoo jiwoo jiwoo jiwoo jiwoo jiwoo"
						bind:value={confirmMnemonic}
					></textarea>
					{#if errors[2]}
						<span class="text-red-500 text-sm">{errors[2]}</span>
					{/if}
				{/if}
				{#if current_stage === 3}
					<div class="my-2">
						<p>Masukkan PIN:</p>
					</div>
					<div class="flex items-center gap-4">
						{#each new Array(6) as _, i}
							<div
								class={cn('size-5 rounded-full bg-zinc-200', pin[i] !== undefined && 'bg-zinc-800')}
							></div>
						{/each}
					</div>
					<div class="flex-1 grid grid-cols-3 gap-2 w-full mb-4">
						{#each new Array(9) as _, i}
							<div class="flex items-center justify-center">
								<button
									class="border border-zinc-200 bg-zinc-100 rounded-full size-20 font-medium text-lg"
									onclick={() => enterPin(i + 1)}>{i + 1}</button
								>
							</div>
						{/each}
						<div class="flex items-center justify-center col-start-2">
							<button
								class="border border-zinc-200 bg-zinc-100 rounded-full size-20 font-medium text-lg"
								onclick={() => enterPin(0)}>0</button
							>
						</div>

						<div class="flex items-center justify-center">
							<button
								class="border border-zinc-200 bg-zinc-100 rounded-full size-20 flex items-center justify-center"
								onclick={backspacePin}
								><DeleteIcon strokeWidth={1} />
							</button>
						</div>
					</div>
				{/if}
				{#if current_stage === 4}
					<div class="my-2">
						<p>Masukkan kembali PIN Anda:</p>
						{#if errors[4]}
							<div
								class="w-full bg-red-100 border border-red-300 rounded-md flex items-center justify-center"
							>
								<span class="text-red-500 text-sm">{errors[4]}</span>
							</div>
						{/if}
					</div>
					<div class="flex items-center gap-4">
						{#each new Array(6) as _, i}
							<div
								class={cn(
									'size-5 rounded-full bg-zinc-200',
									confirmPin[i] !== undefined && 'bg-zinc-800'
								)}
							></div>
						{/each}
					</div>
					<div class="flex-1 grid grid-cols-3 gap-2 w-full mb-4">
						{#each new Array(9) as _, i}
							<div class="flex items-center justify-center">
								<button
									class="border border-zinc-200 bg-zinc-100 rounded-full size-20 font-medium text-lg"
									onclick={() => reenterPin(i + 1)}>{i + 1}</button
								>
							</div>
						{/each}
						<div class="flex items-center justify-center col-start-2">
							<button
								class="border border-zinc-200 bg-zinc-100 rounded-full size-20 font-medium text-lg"
								onclick={() => reenterPin(0)}>0</button
							>
						</div>
						<div class="flex items-center justify-center">
							<button
								class="border border-zinc-200 bg-zinc-100 rounded-full size-20 flex items-center justify-center"
								onclick={backspaceConfirmPin}
								><DeleteIcon strokeWidth={1} />
							</button>
						</div>
					</div>
				{/if}
				{#if current_stage === 5}
					<div class="flex flex-col w-full gap-2">
						<p>Silakan masukkan NIK Anda:</p>
						<input
							bind:value={nik}
							id="nik"
							type="text"
							placeholder="1232142131"
							class="input-text"
						/>
						{nik}
					</div>
				{/if}
			</div>
			<div>
				<button
					class="button"
					onclick={next_actions[current_stage as keyof typeof next_actions].action}
					>{next_actions[current_stage as keyof typeof next_actions].label}</button
				>
			</div>
		</div>
	{/if}
</div>
