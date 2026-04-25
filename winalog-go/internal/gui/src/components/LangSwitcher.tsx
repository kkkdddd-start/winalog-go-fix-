import { useI18n } from '../locales/I18n'
import './LangSwitcher.css'

export default function LangSwitcher() {
  const { locale, toggleLocale } = useI18n()

  return (
    <button className="lang-switcher" onClick={toggleLocale}>
      {locale === 'zh' ? 'EN' : '中'}
    </button>
  )
}