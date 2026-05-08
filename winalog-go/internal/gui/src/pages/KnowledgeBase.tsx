import { useState, useMemo, useCallback, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Marked } from 'marked'
import kbData from '../docs/kb-data.json'

const marked = new Marked()

const sections = kbData.sections as Array<{
  type: string
  id: string
  title: string
  section: string
  subsection: string
  content: string
}>

const searchIndex = kbData.searchIndex as Array<{
  id: string
  title: string
  section: string
  searchable: string
}>

interface TOCGroup {
  title: string
  items: Array<{ id: string; title: string; eventId: string }>
}

function buildTOC(): TOCGroup[] {
  const groups: TOCGroup[] = []
  let currentGroup: TOCGroup | null = null

  for (const item of searchIndex) {
    if (!currentGroup || item.section !== currentGroup.title) {
      currentGroup = { title: item.section, items: [] }
      groups.push(currentGroup)
    }
    currentGroup.items.push({
      id: item.id,
      title: item.title,
      eventId: item.id,
    })
  }
  return groups
}

const toc = buildTOC()

function renderMarkdown(content: string): string {
  return marked.parse(content) as string
}

export default function KnowledgeBase() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [activeSection, setActiveSection] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [sidebarOpen, setSidebarOpen] = useState(true)

  useEffect(() => {
    const id = searchParams.get('id')
    if (id) {
      setActiveSection(id)
    }
  }, [searchParams])

  const activeData = useMemo(() => {
    if (!activeSection) return null
    return sections.find(s => s.id === activeSection) || null
  }, [activeSection])

  const searchResults = useMemo(() => {
    if (!searchQuery.trim()) return []
    const q = searchQuery.toLowerCase().trim()
    return searchIndex
      .filter(item => item.searchable.includes(q))
      .slice(0, 50)
  }, [searchQuery])

  const handleSectionClick = useCallback((id: string) => {
    setActiveSection(id)
    setSearchParams({ id })
    setSidebarOpen(false)
  }, [setSearchParams])

  const handleSearchSelect = useCallback((id: string) => {
    setActiveSection(id)
    setSearchParams({ id })
    setSearchQuery('')
  }, [setSearchParams])

  const handleBack = useCallback(() => {
    setActiveSection(null)
    setSearchParams({})
    setSidebarOpen(true)
  }, [setSearchParams])

  return (
    <div className="kb-page">
      <div className="kb-header">
        <h2>Windows 事件知识库</h2>
        <p className="kb-subtitle">共 {kbData.totalEventIds} 个事件 ID 参考条目</p>
      </div>

      <div className="kb-layout">
        {/* Sidebar TOC */}
        <div className={`kb-sidebar ${sidebarOpen ? 'open' : ''}`}>
          <div className="kb-search">
            <input
              type="text"
              placeholder="搜索事件 ID 或关键词..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
            />
          </div>

          {searchQuery ? (
            <div className="kb-search-results">
              {searchResults.length === 0 ? (
                <div className="kb-no-results">未找到匹配结果</div>
              ) : (
                searchResults.map(item => (
                  <button
                    key={item.id}
                    className={`kb-search-item ${activeSection === item.id ? 'active' : ''}`}
                    onClick={() => handleSearchSelect(item.id)}
                  >
                    <span className="kb-event-id">{item.id}</span>
                    <span className="kb-event-title">{item.title}</span>
                  </button>
                ))
              )}
            </div>
          ) : (
            <div className="kb-toc">
              {toc.map(group => (
                <div key={group.title} className="kb-toc-group">
                  <div className="kb-toc-group-title">{group.title}</div>
                  <div className="kb-toc-items">
                    {group.items.map(item => (
                      <button
                        key={item.id}
                        className={`kb-toc-item ${activeSection === item.id ? 'active' : ''}`}
                        onClick={() => handleSectionClick(item.id)}
                      >
                        {item.title}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Toggle sidebar button */}
        {!sidebarOpen && (
          <button className="kb-sidebar-toggle" onClick={() => setSidebarOpen(true)}>
            ☰
          </button>
        )}

        {/* Main content */}
        <div className="kb-content">
          {!activeData ? (
            <div className="kb-welcome">
              <h3>欢迎使用 Windows 事件知识库</h3>
              <p>从左侧目录选择一个事件 ID，或使用搜索框快速查找。</p>
              <div className="kb-quick-links">
                <h4>常用事件 ID</h4>
                <div className="kb-quick-grid">
                  {[
                    { id: '4624', desc: '登录成功' },
                    { id: '4625', desc: '登录失败' },
                    { id: '4648', desc: '显式凭据登录' },
                    { id: '4672', desc: '特权分配' },
                    { id: '4688', desc: '新进程创建' },
                    { id: '4776', desc: 'NTLM 凭据验证' },
                    { id: '4768', desc: 'TGT 请求' },
                    { id: '4769', desc: 'TGS 请求' },
                    { id: '4720', desc: '账户已创建' },
                    { id: '1102', desc: '安全日志已清除' },
                  ].map(item => (
                    <button
                      key={item.id}
                      className="kb-quick-item"
                      onClick={() => handleSectionClick(item.id)}
                    >
                      <span className="kb-quick-id">{item.id}</span>
                      <span className="kb-quick-desc">{item.desc}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="kb-article">
              <div className="kb-article-header">
                <button className="kb-back-btn" onClick={handleBack}>
                  ← 返回目录
                </button>
                <h3>{activeData.title}</h3>
                {activeData.subsection && (
                  <div className="kb-article-breadcrumb">{activeData.section} / {activeData.subsection}</div>
                )}
              </div>
              <div
                className="kb-article-body"
                dangerouslySetInnerHTML={{ __html: renderMarkdown(activeData.content) }}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
