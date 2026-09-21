import 'server-only'
import type {NextRequest} from 'next/server'
import type {SupabaseClient} from '@supabase/supabase-js'
export const MAX_ATTEMPTS=8,WINDOW_MINUTES=15,CODE_ERROR='Dieser Code ist ungueltig, abgelaufen oder schon benutzt.'
export function requirePepper(){const p=process.env.INVITE_CODE_PEPPER;if(!p||p.length<32)throw new Error('INVITE_CODE_PEPPER fehlt oder ist zu kurz');return p}
export async function clientIpHash(r:NextRequest,p:string){const ip=r.headers.get('x-forwarded-for')?.split(',')[0]?.trim()||r.headers.get('x-real-ip')||'unbekannt';const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(p),{name:'HMAC',hash:'SHA-256'},false,['sign']);const digest=await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(ip));return Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('')}
export async function throttled(a:SupabaseClient,ip:string){const since=new Date(Date.now()-WINDOW_MINUTES*60000).toISOString();const {count}=await a.from('redeem_attempts').select('id',{count:'exact',head:true}).eq('ip_hash',ip).eq('success',false).gte('created_at',since);return(count??0)>=MAX_ATTEMPTS}
export async function noteAttempt(a:SupabaseClient,ip:string,success:boolean){await a.from('redeem_attempts').insert({ip_hash:ip,success})}
export async function issueSession(a:SupabaseClient,email:string){const {data,error}=await a.auth.admin.generateLink({type:'magiclink',email});return error?null:data?.properties?.hashed_token??null}
