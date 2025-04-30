import { z } from 'zod';

export const ActivationSchema = z.object({
	id: z
		.string({
			required_error: 'ID wajib diisi.',
			invalid_type_error: 'ID tidak valid.'
		})
		.trim()
		.min(1, { message: 'ID wajib diisi.' })
		.transform((val) => val.trim()),
	activationKey: z
		.string({
			required_error: 'Kunci Aktivasi wajib diisi.',
			invalid_type_error: 'Kunci Aktivasi tidak valid.'
		})
		.trim()
		.min(1, { message: 'Kunci Aktivasi wajib diisi.' })
		.max(36, { message: 'Kunci Aktivasi tidak valid.' })
		.transform((val) => val.trim())
});
