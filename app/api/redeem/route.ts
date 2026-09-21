import {NextResponse,type NextRequest} from 'next/server'
import {createAdminClient} from '@/lib/supabase/admin'
import {hashCode} from '@/lib/hash'
import {normalizeCode,DEVICE_AUTH_LEN,INVITE_LEN} from '@/lib/codes'
import {CODE_ERROR,clientIpHash,issueSession,noteAttempt,requirePepper,throttled,WINDOW_MINUTES} from '@/lib/auth-helpers'
export const runtime='nodejs'
export const dynamic='force-dynamic'
function randomBytes(length:number){const bytes=new Uint8Array(length);crypto.getRandomValues(bytes);return bytes}
function toBase64Url(bytes:Uint8Array){let binary='';for(const b of bytes)binary+=String.fromCharCode(b);return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
export async function POST(request:NextRequest){
 let pepper:string;try{pepper=requirePepper()}catch{return NextResponse.json({error:'Server ist nicht fertig eingerichtet.'},{status:500})}
 const body=await request.json().catch(()=>null) as any;if(!body)return NextResponse.json({error:'Ungueltige Anfrage.'},{status:400})
 const auth=normalizeCode(String(body.authPart??'')),username=String(body.username??'').trim()
 if(auth.length!==INVITE_LEN&&auth.length!==DEVICE_AUTH_LEN)return NextResponse.json({error:CODE_ERROR},{status:400})
 const admin=createAdminClient(),ipHash=await clientIpHash(request,pepper);if(await throttled(admin,ipHash))return NextResponse.json({error:`Zu viele Versuche. Bitte in ${WINDOW_MINUTES} Minuten noch einmal.`},{status:429})
 const now=new Date().toISOString(),codeHash=await hashCode(auth,pepper),{data:claimed}=await admin.from('invite_codes').update({used_at:now}).eq('code_hash',codeHash).is('used_at',null).or(`expires_at.is.null,expires_at.gt.${now}`).select('id,kind,for_user,payload,payload_iv,payload_salt').maybeSingle()
 if(!claimed){await noteAttempt(admin,ipHash,false);return NextResponse.json({error:CODE_ERROR},{status:400})}
 if(claimed.kind==='device'){const {data:u}=await admin.auth.admin.getUserById(claimed.for_user);if(!u?.user?.email)return NextResponse.json({error:CODE_ERROR},{status:400});const tokenHash=await issueSession(admin,u.user.email);if(!tokenHash)return NextResponse.json({error:'Anmeldung fehlgeschlagen.'},{status:500});await admin.from('invite_codes').update({payload:null,payload_iv:null,payload_salt:null,used_by:claimed.for_user}).eq('id',claimed.id);return NextResponse.json({kind:'device',tokenHash,userId:claimed.for_user,payload:claimed.payload,payloadIv:claimed.payload_iv,payloadSalt:claimed.payload_salt})}
 if(!/^[A-Za-z0-9_.-]{3,24}$/.test(username)){await admin.from('invite_codes').update({used_at:null}).eq('id',claimed.id);return NextResponse.json({error:'Der Benutzername ist ungueltig.'},{status:400})}
 const email=`${crypto.randomUUID()}@${process.env.INVITE_EMAIL_DOMAIN||'invite.local'}`;const {data:created,error}=await admin.auth.admin.createUser({email,email_confirm:true,password:toBase64Url(randomBytes(48))})
 if(error||!created?.user){await admin.from('invite_codes').update({used_at:null}).eq('id',claimed.id);return NextResponse.json({error:'Konto konnte nicht angelegt werden.'},{status:500})}
 const {error:pe}=await admin.from('profiles').insert({id:created.user.id,username});if(pe){await admin.auth.admin.deleteUser(created.user.id);await admin.from('invite_codes').update({used_at:null}).eq('id',claimed.id);return NextResponse.json({error:'Benutzername ist bereits vergeben.'},{status:409})}
 const tokenHash=await issueSession(admin,email);await admin.from('invite_codes').update({used_by:created.user.id}).eq('id',claimed.id);await noteAttempt(admin,ipHash,true)
 return NextResponse.json({kind:'invite',tokenHash,userId:created.user.id,username})
}