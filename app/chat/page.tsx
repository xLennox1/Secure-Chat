import { redirect } from 'next/navigation'
import { createClient } from '@/lib/supabase/server'
import ChatClient from './chat-client'

export const dynamic = 'force-dynamic'

export default async function ChatPage() {
  const supabase = await createClient()

  const { data: { user } } = await supabase.auth.getUser()
  if (!user) redirect('/')

  const { data: me } = await supabase
    .from('profiles')
    .select('id, username')
    .eq('id', user.id)
    .maybeSingle()

  if (!me) redirect('/')

  return <ChatClient me={me} />
}
