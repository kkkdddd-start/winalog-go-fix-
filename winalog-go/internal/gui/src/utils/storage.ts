/**
 * localStorage 安全工具类
 * 用于处理隐私模式/无痕模式下 localStorage 不可用的情况
 */

// 检查 localStorage 是否可用
function isLocalStorageAvailable(): boolean {
  try {
    const testKey = '__storage_test__'
    localStorage.setItem(testKey, testKey)
    localStorage.removeItem(testKey)
    return true
  } catch (e) {
    return false
  }
}

// 内存存储 (隐私模式备用方案)
const memoryStorage: Record<string, string> = {}

/**
 * 安全的 setItem
 * @param key 存储键
 * @param value 存储值
 * @returns 是否成功存储
 */
export function safeSetItem(key: string, value: string): boolean {
  try {
    if (isLocalStorageAvailable()) {
      localStorage.setItem(key, value)
      return true
    }
    // 隐私模式降级到内存存储
    memoryStorage[key] = value
    console.warn('localStorage unavailable, using memory storage')
    return true
  } catch (e) {
    console.error('localStorage setItem failed:', e)
    memoryStorage[key] = value
    return false
  }
}

/**
 * 安全的 getItem
 * @param key 存储键
 * @param defaultValue 默认值
 * @returns 存储的值或默认值
 */
export function safeGetItem(key: string, defaultValue: string = ''): string {
  try {
    if (isLocalStorageAvailable()) {
      const value = localStorage.getItem(key)
      return value !== null ? value : (memoryStorage[key] || defaultValue)
    }
    return memoryStorage[key] || defaultValue
  } catch (e) {
    console.error('localStorage getItem failed:', e)
    return memoryStorage[key] || defaultValue
  }
}

/**
 * 安全的 removeItem
 * @param key 存储键
 * @returns 是否成功删除
 */
export function safeRemoveItem(key: string): boolean {
  try {
    if (isLocalStorageAvailable()) {
      localStorage.removeItem(key)
    }
    delete memoryStorage[key]
    return true
  } catch (e) {
    console.error('localStorage removeItem failed:', e)
    delete memoryStorage[key]
    return false
  }
}

/**
 * 安全的 JSON 存储
 * @param key 存储键
 * @param data 要存储的对象
 * @returns 是否成功存储
 */
export function safeSetJSON<T>(key: string, data: T): boolean {
  try {
    const value = JSON.stringify(data)
    return safeSetItem(key, value)
  } catch (e) {
    console.error('safeSetJSON failed:', e)
    return false
  }
}

/**
 * 安全的 JSON 读取
 * @param key 存储键
 * @param defaultValue 默认值
 * @returns 解析后的对象或默认值
 */
export function safeGetJSON<T>(key: string, defaultValue: T): T {
  try {
    const value = safeGetItem(key, '')
    if (!value) return defaultValue
    return JSON.parse(value) as T
  } catch (e) {
    console.error('safeGetJSON failed:', e)
    return defaultValue
  }
}
