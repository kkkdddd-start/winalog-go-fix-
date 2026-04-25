package live

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/types"
)

type Bookmark struct {
	mu       sync.RWMutex
	lastTime time.Time
	lastID   int64
	path     string
}

func NewBookmark() *Bookmark {
	return &Bookmark{
		lastTime: time.Time{},
		lastID:   -1,
	}
}

func (b *Bookmark) Update(event *types.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if event.Timestamp.After(b.lastTime) {
		b.lastTime = event.Timestamp
	}
	if event.ID > b.lastID {
		b.lastID = event.ID
	}
}

func (b *Bookmark) IsAfterLastBookmark(event *types.Event) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if event.Timestamp.Before(b.lastTime) {
		return true
	}
	if event.Timestamp.Equal(b.lastTime) && event.ID <= b.lastID {
		return true
	}
	return false
}

func (b *Bookmark) ShouldSkip(event *types.Event) bool {
	return b.IsAfterLastBookmark(event)
}

func (b *Bookmark) IsDuplicate(event *types.Event) bool {
	return b.ShouldSkip(event)
}

func (b *Bookmark) GetLastTime() time.Time {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.lastTime
}

func (b *Bookmark) GetLastID() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.lastID
}

func (b *Bookmark) SetPath(path string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.path = path
}

func (b *Bookmark) GetPath() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.path
}

func (b *Bookmark) Save() error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.path == "" {
		return nil
	}

	data, err := json.Marshal(struct {
		LastTime time.Time `json:"last_time"`
		LastID   int64     `json:"last_id"`
		Path     string    `json:"path"`
	}{
		LastTime: b.lastTime,
		LastID:   b.lastID,
		Path:     b.path,
	})

	if err != nil {
		return err
	}

	return os.WriteFile(b.path, data, 0644)
}

func (b *Bookmark) Load() error {
	if b.path == "" {
		return nil
	}

	data, err := os.ReadFile(b.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var bookmarkData struct {
		LastTime time.Time `json:"last_time"`
		LastID   int64     `json:"last_id"`
		Path     string    `json:"path"`
	}

	if err := json.Unmarshal(data, &bookmarkData); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastTime = bookmarkData.LastTime
	b.lastID = bookmarkData.LastID

	return nil
}

func (b *Bookmark) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastTime = time.Time{}
	b.lastID = -1
}

type BookmarkManager struct {
	mu        sync.RWMutex
	bookmarks map[string]*Bookmark
}

func NewBookmarkManager() *BookmarkManager {
	return &BookmarkManager{
		bookmarks: make(map[string]*Bookmark),
	}
}

func (bm *BookmarkManager) GetBookmark(name string) *Bookmark {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.bookmarks[name]
}

func (bm *BookmarkManager) SetBookmark(name string, bookmark *Bookmark) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.bookmarks[name] = bookmark
}

func (bm *BookmarkManager) RemoveBookmark(name string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	delete(bm.bookmarks, name)
}

func (bm *BookmarkManager) ListBookmarks() []string {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	names := make([]string, 0, len(bm.bookmarks))
	for name := range bm.bookmarks {
		names = append(names, name)
	}
	return names
}
