import 'server-only'
import crypto from 'node:crypto'
export const hashCode = (authPart: string, pepper: string) =>
  crypto.createHmac('sha256', pepper).update(authPart).digest('hex')
