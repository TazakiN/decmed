import type { NavLink } from './types';

export interface AuthContext {
	getNav: () => NavLink[];
}
