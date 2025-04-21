import {invoke} from "@tauri-apps/api/core"
import type {PageLoad} from "./$types"
import {redirect} from "@sveltejs/kit"

export const load: PageLoad = async (event) => {
    const is_session = await invoke('is_session_exist') as boolean
    if (is_session) {
        throw redirect(307, '/dashboard')
    }
}