import { AUTH_CONTEXT_DEFAULT_KEY } from '$lib/constants';
import type { AuthContext } from '$lib/interfaces';
import type { NavLink, Role } from '$lib/types';
import { getContext, setContext } from 'svelte';

class Auth implements AuthContext {
	role = $state<Role>('admin');
	constructor() {}

	getNav = () => {
		const defaultNav: NavLink[] = [
			{
				label: 'Home',
				link: `/dashboard`,
				pageTitle: 'Home'
			},
			{
				label: 'Profile',
				link: `/dashboard/profile`,
				pageTitle: 'Profile'
			}
		];

		switch (this.role) {
			case 'admin': {
				return [...defaultNav];
			}
			default: {
				return defaultNav;
			}
		}
	};
}

export const getAuthContext = (key = AUTH_CONTEXT_DEFAULT_KEY) => {
	return getContext<Auth>(key);
};

export const createAuthContext = (key = AUTH_CONTEXT_DEFAULT_KEY) => {
	const authContext = new Auth();
	return setContext(key, authContext);
};
