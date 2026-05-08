#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const MD_FILE = path.resolve(__dirname, '../../../docs/guides/WINDOWS_EVENT_ID.md');
const OUTPUT_FILE = path.resolve(__dirname, '../src/docs/kb-data.json');

function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^\w\u4e00-\u9fa5]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, 50);
}

function cleanContent(contentLines) {
  if (!contentLines || contentLines.length === 0) return '';
  const trimmed = contentLines.join('\n').trim();
  if (!trimmed) return '';
  
  const lines = trimmed.split('\n');
  const firstLine = lines[0] || '';
  const isHeader = /^#{1,4}\s/.test(firstLine);
  
  const cleanLines = isHeader ? lines.slice(1) : lines;
  return cleanLines.join('\n').trim();
}

function parseMarkdown(md) {
  const lines = md.split('\n');
  const sections = [];
  const searchIndex = [];

  let currentH2 = null;
  let currentH3 = null;
  let currentH4 = null;
  let currentContent = [];
  let h3Description = '';
  const usedIds = new Set();

  function getUniqueId(baseId) {
    if (!usedIds.has(baseId)) {
      usedIds.add(baseId);
      return baseId;
    }
    let suffix = 2;
    while (usedIds.has(`${baseId}_${suffix}`)) {
      suffix++;
    }
    const uniqueId = `${baseId}_${suffix}`;
    usedIds.add(uniqueId);
    return uniqueId;
  }

  function flushSection() {
    if (currentH4) {
      const content = cleanContent(currentContent);
      if (content) {
        const id = getUniqueId(currentH4.id);
        sections.push({
          type: 'event',
          id: id,
          title: currentH4.title,
          section: currentH2 ? currentH2.title : '',
          subsection: currentH3 ? currentH3.title : '',
          description: h3Description,
          content: content,
        });
        searchIndex.push({
          id: id,
          title: currentH4.title,
          section: currentH2 ? currentH2.title : '',
          subsection: currentH3 ? currentH3.title : '',
          content: content,
          searchable: `${currentH4.id} ${currentH4.title} ${currentH3 ? currentH3.title : ''} ${currentH2 ? currentH2.title : ''} ${content}`.toLowerCase(),
        });
      }
    }
    currentH4 = null;
    currentContent = [];
  }

  function flushH3() {
    flushSection(); // Flush any pending H4 first
    
    if (currentH3 && currentContent.length > 0) {
      const content = cleanContent(currentContent);
      if (content) {
        const baseId = slugify(currentH3.title);
        const id = getUniqueId(baseId);
        sections.push({
          type: 'section',
          id: id,
          title: currentH3.title,
          section: currentH2 ? currentH2.title : '',
          subsection: currentH3.title,
          content: content,
        });
        searchIndex.push({
          id: id,
          title: currentH3.title,
          section: currentH2 ? currentH2.title : '',
          subsection: currentH3.title,
          content: content,
          searchable: `${currentH3.title} ${currentH2 ? currentH2.title : ''} ${content}`.toLowerCase(),
        });
      }
      currentContent = [];
    }
    h3Description = '';
    currentH3 = null;
  }

  function flushH2() {
    flushH3();
    currentH2 = null;
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const h4Match = line.match(/^####\s+(.+)$/);
    const h3Match = line.match(/^###\s+(.+)$/);
    const h2Match = line.match(/^##\s+(.+)$/);

    if (h4Match) {
      // If we are currently inside an H4, flush it
      if (currentH4) {
        flushSection();
      } 
      // If we are inside H3 but haven't seen H4 yet, currentContent is H3 description
      else if (currentH3) {
        const desc = cleanContent(currentContent);
        if (desc) h3Description = desc;
        currentContent = [];
      }
      
      // Start new H4
      const title = h4Match[1].trim();
      let idMatch = title.match(/(?:^####\s*)?(?:EventID\s+)?(\d+)\s*[-–—]/);
      let baseId = idMatch ? idMatch[1] : slugify(title);
      currentH4 = { id: baseId, title };
      currentContent.push(line);
      
    } else if (h3Match) {
      flushH3();
      currentH3 = { title: h3Match[1].trim() };
      currentContent.push(line);
      
    } else if (h2Match) {
      flushH2();
      currentH2 = { title: h2Match[1].trim() };
      currentContent.push(line);
      
    } else {
      currentContent.push(line);
    }
  }
  flushH2();

  return { sections, searchIndex };
}

const md = fs.readFileSync(MD_FILE, 'utf-8');
const { sections, searchIndex } = parseMarkdown(md);

const output = {
  version: '1.4',
  generatedAt: new Date().toISOString(),
  totalSections: sections.length,
  totalEventIds: searchIndex.length,
  sections,
  searchIndex,
  eventIds: searchIndex.map(item => item.id).filter(Boolean),
  toc: searchIndex.map(item => ({
    id: item.id,
    title: item.title,
    section: item.section,
    subsection: item.subsection,
  })),
};

fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output), 'utf-8');
console.log(`Generated kb-data.json: ${sections.length} sections, ${searchIndex.length} event IDs`);
