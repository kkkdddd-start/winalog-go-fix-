import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import kbData from '../docs/kb-data.json'

const searchIndex = kbData.searchIndex as Array<{
  id: string
  title: string
  section: string
  searchable: string
}>

const sections = kbData.sections as Array<{
  id: string
  content: string
}>

interface EventIDTooltipProps {
  eventId: string
  children: React.ReactNode
}

export default function EventIDTooltip({ eventId, children }: EventIDTooltipProps) {
  const [visible, setVisible] = useState(false)
  const [position, setPosition] = useState({ top: 0, left: 0 })
  const triggerRef = useRef<HTMLSpanElement>(null)
  const tooltipRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()

  const searchData = searchIndex.find(item => item.id === eventId)
  const sectionData = sections.find(s => s.id === eventId)

  const show = (e: React.MouseEvent) => {
    e.stopPropagation()
    if (!searchData) return
    const rect = (e.target as HTMLElement).getBoundingClientRect()
    setPosition({ top: rect.bottom + 8, left: rect.left })
    setVisible(true)
  }

  useEffect(() => {
    if (!visible) return
    const handleClickOutside = (e: MouseEvent) => {
      if (tooltipRef.current && !tooltipRef.current.contains(e.target as Node)) {
        setVisible(false)
      }
    }
    const handleScroll = () => setVisible(false)
    document.addEventListener('click', handleClickOutside)
    window.addEventListener('scroll', handleScroll, true)
    return () => {
      document.removeEventListener('click', handleClickOutside)
      window.removeEventListener('scroll', handleScroll, true)
    }
  }, [visible])

  return (
    <>
      <span
        ref={triggerRef}
        className="event-tooltip-trigger"
        onClick={show}
        onMouseEnter={show}
      >
        {children}
      </span>
      {visible && searchData && (
        <div
          ref={tooltipRef}
          className="event-tooltip"
          style={{ top: position.top, left: position.left }}
        >
          <div className="event-tooltip-header">
            <span className="event-tooltip-id">{searchData.id}</span>
            <span className="event-tooltip-title">{searchData.title}</span>
          </div>
          {sectionData && (
            <div className="event-tooltip-body">
              <p className="event-tooltip-desc">
                {sectionData.content.split('\n').filter(l => l.startsWith('**一句话解释**'))[0]
                  ?.replace(/\*\*一句话解释\*\*[:：]\s*/, '')
                  ?.slice(0, 120) || '点击查看详情'}
              </p>
              <button
                className="event-tooltip-link"
                onClick={() => {
                  setVisible(false)
                  navigate(`/docs?id=${searchData.id}`)
                }}
              >
                查看完整参考 →
              </button>
            </div>
          )}
        </div>
      )}
    </>
  )
}
