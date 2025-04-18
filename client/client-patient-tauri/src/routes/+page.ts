import { invoke } from "@tauri-apps/api/core"
import type { PageLoad } from "./$types"
import { redirect } from "@sveltejs/kit"

export const load: PageLoad = async (event) => {
  const is_session = await invoke('is_session_exist') as boolean
  if (!is_session && !event.url.pathname.startsWith('/auth')) {
    throw redirect(307, '/auth/signin')
  }
  if (is_session && !event.url.pathname.startsWith('/dashboard')) {
    throw redirect(307, '/dashboard')
  }
}