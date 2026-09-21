import {NextResponse,type NextRequest} from 'next/server'
import {createClient} from '@/lib/supabase/server'
import {createAdminClient} from '@/lib/supabase/admin'
import {hashCode} from '@/lib/hash'
import {normalizeCode,DEVICE_AUTH_LEN} from '@/lib/codes'
import {requirePepper} from '@/lib/auth-helpers'
export const runtime='nodejs'
export const dynamic='force-dynamic'
export async function POST(request:NextRequest){
 let pepper:string;try{pepper=requirePepper()}catch{return NextResponse.json({error:'Server ist nicht fertig eingerichtet.'},{status:500})}
 const {data:{user}}=await (await createClient()).auth.getUser();if(!user)return NextResponse.json({error:'Nicht angemeldet.'},{status:401})
 const body=await request.json().catch(()=>null) as any;if(!body)return NextResponse.json({error:'Ungueltige Anfrage.'},{status:400})
 const auth=normalizeCode(String(body.authPart??''),DEVICE_AUTH_LEN),payload=String(body.payload??''),payloadIv=String(body.payloadIv??''),payloadSalt=String(body.payloadSalt??'')
 if(auth.length!==DEVICE_AUTH_LEN)return NextResponse.json({error:'Ungueltige Anfrage.'},{status:400})
 const admin=createAdminClient();await admin.from('invite_codes').delete().eq('kind','device').eq('for_user',user.id).is('used_at',null)
 const codeHash=await hashCode(auth,pepper),{error}=await admin.from('invite_codes').insert({kind:'device',for_user:user.id,code_hash:codeHash,expires_at:new Date(Date.now()+600000).toISOString(),payload,payload_iv:payloadIv,payload_salt:payloadSalt})
 if(error)return NextResponse.json({error:'Code konnte nicht angelegt werden.'},{status:500});return NextResponse.json({minutes:10})
}