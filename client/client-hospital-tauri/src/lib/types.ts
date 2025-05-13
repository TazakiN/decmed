export type Role = 'admin' | 'administrative' | 'medical';

export type NavLink = {
	label: string;
	link: string;
	pageTitle: string;
};

export type Account = {
	role: Role;
	name: string;
	id: string;
};
