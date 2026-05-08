const DEBUG_ENABLED = import.meta.env.VITE_WINALOG_DEBUG === 'true'

export const debugLog = (...args: unknown[]): void => {
  if (DEBUG_ENABLED) {
    console.log(...args)
  }
}

export const debugGroup = (label: string, ...args: unknown[]): void => {
  if (DEBUG_ENABLED) {
    console.group(label)
    console.log(...args)
    console.groupEnd()
  }
}
