import { createServerClient } from '@supabase/ssr'
import { NextResponse,type NextRequest } from 'next/server'

function createNonce() {
 const bytes = new Uint8Array(16)
 crypto.getRandomValues(bytes)
 let binary = ''
 for (const byte of bytes) binary += String.fromCharCode(byte)
 return btoa(binary)
}

export async function middleware(request:NextRequest){
 const nonce=createNonce()
 const csp=[`default-src 'self'`,`script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,`style-src 'self' 'unsafe-inline'`,`img-src 'self' data: blob:`,`font-src 'self'`,`connect-src 'self' https://*.supabase.co wss://*.supabase.co`,`frame-ancestors 'none'`,`base-uri 'self'`,`form-action 'self'`].join('; ')
 const requestHeaders=new Headers(request.headers);requestHeaders.set('x-nonce',nonce)
 let response=NextResponse.next({request:{headers:requestHeaders}})
 const supabase=createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!,process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,{cookies:{getAll:()=>request.cookies.getAll(),setAll:(list)=>{list.forEach(({name,value,options})=>request.cookies.set(name,value));response=NextResponse.next({request:{headers:requestHeaders}});list.forEach(({name,value,options})=>response.cookies.set(name,value,options))}}})
 await supabase.auth.getUser()
 response.headers.set('Content-Security-Policy',csp)
 return response
}
export const config={matcher:['/((?!_next/static|_next/image|favicon.ico).*)']}
