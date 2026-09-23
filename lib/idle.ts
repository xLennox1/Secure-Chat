'use client'

import { useEffect, useRef, useState } from 'react'

const EVENTS = ['pointerdown', 'keydown', 'wheel', 'touchstart', 'focus'] as const

export function useIdleLock(minutes: number, onIdle: () => void) {
  const [secondsLeft, setSecondsLeft] = useState<number | null>(null)
  const deadline = useRef(Date.now() + minutes * 60_000)
  const fired = useRef(false)
  const callback = useRef(onIdle)
  callback.current = onIdle

  useEffect(() => {
    const limit = minutes * 60_000
    const warnAt = Math.min(30_000, limit / 2)
    const reset = () => {
      if (fired.current) return
      deadline.current = Date.now() + limit
      setSecondsLeft(null)
    }
    const tick = () => {
      if (fired.current) return
      const remaining = deadline.current - Date.now()
      if (remaining <= 0) {
        fired.current = true
        setSecondsLeft(0)
        callback.current()
      } else if (remaining <= warnAt) {
        setSecondsLeft(Math.ceil(remaining / 1000))
      }
    }
    for (const event of EVENTS) window.addEventListener(event, reset, { passive: true })
    document.addEventListener('visibilitychange', tick)
    const timer = window.setInterval(tick, 1000)
    return () => {
      for (const event of EVENTS) window.removeEventListener(event, reset)
      document.removeEventListener('visibilitychange', tick)
      window.clearInterval(timer)
    }
  }, [minutes])
  return secondsLeft
}
