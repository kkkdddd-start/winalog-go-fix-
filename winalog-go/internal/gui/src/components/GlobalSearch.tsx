import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import kbData from '../docs/kb-data.json'

const searchIndex = kbData.searchIndex as Array<{
  id: string
  title: string
  section: string
  searchable: string
}>

interface GlobalSearchProps {
  isOpen: boolean
  onClose: () => void
}

export default function GlobalSearch({ isOpen, onClose }: GlobalSearchProps) {
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)
  const resultsRef = useRef<HTMLDivElement>(null)

  const results = query.trim()
    ? searchIndex
        .filter(item => item.searchable.includes(query.toLowerCase().trim()))
        .slice(0, 15)
    : []

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus()
      setQuery('')
      setSelectedIndex(0)
    }
  }, [isOpen])

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        if (isOpen) onClose()
      }
      if (e.key === 'Escape' && isOpen) onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  const handleSelect = useCallback((id: string) => {
    navigate(`/docs?id=${id}`)
    onClose()
  }, [navigate, onClose])

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSelectedIndex(i => Math.min(i + 1, results.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSelectedIndex(i => Math.max(i - 1, 0))
    } else if (e.key === 'Enter' && results[selectedIndex]) {
      handleSelect(results[selectedIndex].id)
    }
  }, [results, selectedIndex, handleSelect])

  if (!isOpen) return null

  return (
    <div className="global-search-overlay" onClick={onClose}>
      <div className="global-search" onClick={e => e.stopPropagation()}>
        <div className="global-search-input">
          <span className="global-search-icon">&#128269;</span>
          <input
            ref={inputRef}
            type="text"
            placeholder="搜索事件 ID、标题或关键词..."
            value={query}
            onChange={e => { setQuery(e.target.value); setSelectedIndex(0) }}
            onKeyDown={handleKeyDown}
          />
          <kbd className="global-search-kbd">ESC</kbd>
        </div>
        {results.length > 0 && (
          <div ref={resultsRef} className="global-search-results">
            {results.map((item, idx) => (
              <button
                key={item.id}
                className={`global-search-item ${idx === selectedIndex ? 'active' : ''}`}
                onClick={() => handleSelect(item.id)}
                onMouseEnter={() => setSelectedIndex(idx)}
              >
                <span className="global-search-event-id">{item.id}</span>
                <span className="global-search-title">{item.title}</span>
                <span className="global-search-section">{item.section}</span>
              </button>
            ))}
          </div>
        )}
        {query.trim() && results.length === 0 && (
          <div className="global-search-empty">未找到匹配结果</div>
        )}
      </div>
    </div>
  )
}
