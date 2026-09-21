export const ALPHABET='23456789ABCDEFGHJKMNPQRSTVWXYZ'
export const INVITE_LEN=16
export const DEVICE_LEN=20
export const DEVICE_AUTH_LEN=10
export type CodeKind='invite'|'device'
export function kindOf(normalized:string):CodeKind|null{if(normalized.length===INVITE_LEN)return'invite';if(normalized.length===DEVICE_LEN)return'device';return null}
export const authPart=(normalized:string)=>normalized.length===DEVICE_LEN?normalized.slice(0,DEVICE_AUTH_LEN):normalized
export const secretPart=(normalized:string)=>normalized.length===DEVICE_LEN?normalized.slice(DEVICE_AUTH_LEN):''
export function normalizeCode(raw:string,max=DEVICE_LEN){const allowed=new Set(ALPHABET);return[...raw.toUpperCase()].filter(c=>allowed.has(c)).join('').slice(0,max)}
export const formatCode=(normalized:string)=>normalized.match(/.{1,4}/g)?.join('-')??''
export const isCompleteCode=(normalized:string)=>kindOf(normalized)!==null
export function generateCode(length:number){const out:string[]=[];const limit=256-(256%ALPHABET.length);while(out.length<length){const bytes=crypto.getRandomValues(new Uint8Array(length*2));for(const b of bytes)if(b<limit&&out.length<length)out.push(ALPHABET[b%ALPHABET.length])}return out.join('')}
