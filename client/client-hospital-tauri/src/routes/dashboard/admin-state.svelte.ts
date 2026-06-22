import {
	ADMINISTRATIVE_PERSONNEL_ROLE,
	MEDICAL_PERSONNEL_ROLE,
	MEDICAL_PERSONNEL_SUB_ROLES
} from '$lib/constants';
import { addPersonnelSchemas } from '$lib/schema';
import type {
	AddPersonnelSchemaStep2,
	HospitalPersonnel,
	InvokeHospitalAdminAddActivationKeyResponse,
	Role,
	SuccessResponse
} from '$lib/types';
import { tryCatchAsVal } from '$lib/utils';
import { invoke } from '@tauri-apps/api/core';
import { toast } from 'svelte-sonner';
import { superForm, type Infer, type SuperForm, type SuperValidated } from 'sveltekit-superforms';
import { zod } from 'sveltekit-superforms/adapters';

type Constructor = {
	addPersonnelForm: SuperValidated<Infer<AddPersonnelSchemaStep2>>;
};

export class AdminHomeState {
	currentStep = $state(1);
	addPersonnelDialogOpen = $state(false);
	askPin = $state(false);
	isLoadingUpdateActivationKey = $state(false);
	something: Infer<AddPersonnelSchemaStep2> | undefined = undefined;
	addPersonnelFormMeta: SuperForm<Infer<AddPersonnelSchemaStep2>>;
	roles = [
		{
			value: MEDICAL_PERSONNEL_ROLE,
			label: MEDICAL_PERSONNEL_ROLE
		},
		{
			value: ADMINISTRATIVE_PERSONNEL_ROLE,
			label: ADMINISTRATIVE_PERSONNEL_ROLE
		}
	];
	medicalSubRoles = [
		{
			value: MEDICAL_PERSONNEL_SUB_ROLES[0],
			label: 'Dokter'
		},
		{
			value: MEDICAL_PERSONNEL_SUB_ROLES[1],
			label: 'Perawat'
		},
		{
			value: MEDICAL_PERSONNEL_SUB_ROLES[2],
			label: 'Lab Personnel'
		},
		{
			value: MEDICAL_PERSONNEL_SUB_ROLES[3],
			label: 'Apoteker'
		}
	];

	constructor({ addPersonnelForm }: Constructor) {
		this.addPersonnelFormMeta = superForm(addPersonnelForm, {
			validators: false,
			dataType: 'json',
			SPA: true,
			invalidateAll: false,
			onSubmit: async ({ cancel }) => {
				if ((this, this.currentStep === 2)) return;
				cancel();

				const valid = await this.addPersonnelFormMeta.validateForm({ update: true });
				if (valid) {
					if (this.something?.role === MEDICAL_PERSONNEL_ROLE && !this.something.subRole) {
						toast.error('Sub role is required for medical personnel');
						return;
					}

					this.currentStep += 1;
					this.askPin = true;
				}
			},
			onUpdate: async ({ result, form, cancel }) => {
				if (result.type === 'success') {
					if (form.data.role === MEDICAL_PERSONNEL_ROLE && !form.data.subRole) {
						cancel();
						toast.error('Sub role is required for medical personnel');
						return;
					}

					const resInvokeHospitalAdminAddActivationKey = await tryCatchAsVal(async () => {
						return (await invoke('hospital_admin_add_activation_key', {
							personnelIdPart: form.data.id,
							role: form.data.role,
							subRole: form.data.role === MEDICAL_PERSONNEL_ROLE ? form.data.subRole : undefined,
							pin: form.data.pin
						})) as SuccessResponse<InvokeHospitalAdminAddActivationKeyResponse>;
					});

					if (!resInvokeHospitalAdminAddActivationKey.success) {
						cancel();
						console.log(resInvokeHospitalAdminAddActivationKey.error);
						toast.error(resInvokeHospitalAdminAddActivationKey.error);
						return;
					}

					this.askPin = false;
					this.addPersonnelDialogOpen = false;
					this.currentStep = 1;

					this.refetchPersonnels = this.getHospitalPersonnels();
				}
			}
		});

		// ponytail: subscribe to form changes for step validation
		this.addPersonnelFormMeta.form.subscribe((val) => (this.something = val));

		$effect(() => {
			this.addPersonnelFormMeta.options.validators = zod(addPersonnelSchemas[this.currentStep - 1]);
		});
	}

	getHospitalPersonnels = async () => {
		const resInvokeGetHospitalPersonnels = await tryCatchAsVal(async () => {
			return (await invoke('get_hospital_personnels')) as SuccessResponse<{
				personnels: HospitalPersonnel[];
			}>;
		});

		if (!resInvokeGetHospitalPersonnels.success) {
			toast.error(resInvokeGetHospitalPersonnels.error);
			return [];
		}

		return resInvokeGetHospitalPersonnels.data.data.personnels;
	};

	refetchPersonnels = $state<Promise<HospitalPersonnel[]>>(this.getHospitalPersonnels());

	updatePersonnelActivationKey = async ({
		personnelId,
		role,
		subRole
	}: {
		personnelId: string;
		role: Role;
		subRole?: string;
	}) => {
		this.isLoadingUpdateActivationKey = true;

		const resInvokeUpdatePersonnelActivationKey = await tryCatchAsVal(async () => {
			return (await invoke('update_personnel_activation_key', {
				personnelId,
				role,
				subRole: role === MEDICAL_PERSONNEL_ROLE ? subRole : undefined
			})) as SuccessResponse<InvokeHospitalAdminAddActivationKeyResponse>;
		});

		if (!resInvokeUpdatePersonnelActivationKey.success) {
			this.isLoadingUpdateActivationKey = false;
			toast.error(resInvokeUpdatePersonnelActivationKey.error);
			return;
		}

		this.refetchPersonnels = this.getHospitalPersonnels();
		this.isLoadingUpdateActivationKey = false;
		toast.success('Activation key updated successfully');
	};
}
