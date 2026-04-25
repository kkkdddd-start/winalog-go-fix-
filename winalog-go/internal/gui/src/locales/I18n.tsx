import { createContext, useContext, useState, useCallback, ReactNode } from 'react'
import { zh, en, Locale, TranslationKeys } from './index'

type TranslationObject = typeof zh

const translations: Record<Locale, TranslationObject> = { zh, en }

interface I18nContextType {
  locale: Locale
  t: (path: string, params?: Record<string, string | number>) => string
  setLocale: (locale: Locale) => void
  toggleLocale: () => void
}

const I18nContext = createContext<I18nContextType | undefined>(undefined)

function getNestedValue(obj: any, path: string): string {
  const keys = path.split('.')
  let value = obj
  for (const key of keys) {
    if (value && typeof value === 'object' && key in value) {
      value = value[key]
    } else {
      return path
    }
  }
  return typeof value === 'string' ? value : path
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() => {
    const saved = localStorage.getItem('locale')
    return (saved === 'en' || saved === 'zh') ? saved : 'zh'
  })

  const setLocale = useCallback((newLocale: Locale) => {
    setLocaleState(newLocale)
    localStorage.setItem('locale', newLocale)
  }, [])

  const toggleLocale = useCallback(() => {
    const newLocale = locale === 'zh' ? 'en' : 'zh'
    setLocale(newLocale)
  }, [locale, setLocale])

  const t = useCallback((path: string, params?: Record<string, string | number>): string => {
    let text = getNestedValue(translations[locale], path)
    
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        text = text.replace(new RegExp(`\\{${key}\\}`, 'g'), String(value))
      })
    }
    
    return text
  }, [locale])

  return (
    <I18nContext.Provider value={{ locale, t, setLocale, toggleLocale }}>
      {children}
    </I18nContext.Provider>
  )
}

export function useI18n() {
  const context = useContext(I18nContext)
  if (!context) {
    throw new Error('useI18n must be used within I18nProvider')
  }
  return context
}

export { zh, en }
export type { Locale, TranslationKeys }