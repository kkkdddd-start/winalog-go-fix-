#!/usr/bin/env node
// 基于 kb-data.json 的 content 字段自动生成 description 摘要

const fs = require('fs');
const path = require('path');

const DATA_PATH = path.join(__dirname, '../src/docs/kb-data.json');

const data = JSON.parse(fs.readFileSync(DATA_PATH, 'utf-8'));

let updated = 0;
let skipped = 0;

for (const section of data.sections) {
  if (section.description && section.description.trim() !== '') {
    skipped++;
    continue;
  }

  if (!section.content || section.content.trim() === '') {
    skipped++;
    continue;
  }

  const desc = extractDescription(section.content, section.title);
  if (desc) {
    section.description = desc;
    updated++;
  } else {
    skipped++;
  }
}

fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2), 'utf-8');

console.log(`Updated: ${updated} sections`);
console.log(`Skipped: ${skipped} sections`);

/**
 * 从 content 中提取 description 摘要
 */
function extractDescription(content, title) {
  // 策略1: 提取 **描述**: 后面的内容
  const descMatch = content.match(/\*\*描述\*\*\s*:\s*([^\n]+)/);
  if (descMatch && descMatch[1].trim()) {
    return truncate(descMatch[1].trim(), 60);
  }

  // 策略2: 提取 **Description**: 后面的内容 (英文)
  const engDescMatch = content.match(/\*\*Description\*\*\s*:\s*([^\n]+)/i);
  if (engDescMatch && engDescMatch[1].trim()) {
    return truncate(engDescMatch[1].trim(), 60);
  }

  // 策略3: 从标题中提取，去掉 "EventID X - " 前缀
  if (title) {
    const titleMatch = title.match(/^(?:EventID\s*\d+\s*[-–—]\s*)?(.+)$/i);
    if (titleMatch && titleMatch[1].trim()) {
      return truncate(titleMatch[1].trim(), 60);
    }
  }

  // 策略4: 取 content 第一段非空文本
  const lines = content.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('**') && !trimmed.startsWith('|') && !trimmed.startsWith('---')) {
      return truncate(trimmed, 60);
    }
  }

  return null;
}

function truncate(str, maxLen) {
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen).trim() + '...';
}
