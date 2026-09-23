import 'server-only'
import crypto from 'node:crypto'

/** Der Code selbst wird nie gespeichert, nur dieser Hash. */
export const hashCode = (authPart: string, pepper: string) =>
  crypto.createHmac('sha256', pepper).update(authPart).digest('hex')
