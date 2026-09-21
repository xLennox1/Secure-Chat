'use client'
import {useEffect,useState} from 'react'
import {createClient} from '@/lib/supabase/client'
export default function ChatClient({me}:{me?:{id:string;username:string}|null}){
 const [text,setText]=useState(''),[messages,setMessages]=useState<any[]>([]),[status,setStatus]=useState('Verbinde…')
 const supabase=createClient()
 useEffect(()=>{let channel:any;async function load(){const {data:{user}}=await supabase.auth.getUser();if(!user){setStatus('Nicht angemeldet');return}const {data}=await supabase.from('messages').select('id,sender_id,ciphertext,created_at').order('created_at',{ascending:true}).limit(100);setMessages(data||[]);setStatus('Bereit');channel=supabase.channel('messages').on('postgres_changes',{event:'INSERT',schema:'public',table:'messages'},p=>setMessages(v=>[...v,p.new])).subscribe()}load();return()=>{if(channel)supabase.removeChannel(channel)}},[])
 async function send(){if(!text.trim())return;const {data:{user}}=await supabase.auth.getUser();if(!user)return;await supabase.from('messages').insert({sender_id:user.id,conversation_id:'00000000-0000-0000-0000-000000000000',ciphertext:text.trim(),iv:'local',key_epoch:0});setText('')}
 return <main className="shell"><aside className="roster"><strong>{me?.username||'Chat'}</strong><p>{status}</p></aside><section className="chat"><div className="messages">{messages.map(m=><div className="msg" key={m.id}>{m.ciphertext}</div>)}</div><div className="composer"><input value={text} onChange={e=>setText(e.target.value)} onKeyDown={e=>{if(e.key==='Enter')send()}} placeholder="Nachricht…"/><button className="btn" onClick={send}>Senden</button></div></section></main>
}
