package session

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type Session struct {
	mu         sync.RWMutex
	m          map[string]string
	lastAccess time.Time
}

func (s *Session) GetString(key, def string) string {
	s.mu.RLock()
	v, ok := s.m[key]
	s.mu.RUnlock()
	s.touch()
	if ok {
		return v
	}
	return def
}

func (s *Session) SetString(key, val string) {
	s.mu.Lock()
	s.m[key] = val
	s.lastAccess = time.Now()
	s.mu.Unlock()
}

func (s *Session) touch() {
	s.mu.Lock()
	s.lastAccess = time.Now()
	s.mu.Unlock()
}

func (s *Session) LastAccess() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastAccess
}

type Store struct {
	mu              sync.RWMutex
	m               map[string]*Session
	ttl             time.Duration
	cleanupInterval time.Duration
}

func NewStore() *Store {
	st := &Store{
		m:               map[string]*Session{},
		ttl:             30 * time.Minute,
		cleanupInterval: 5 * time.Minute,
	}
	go st.cleanupLoop()
	return st
}

func (st *Store) GetOrCreate(id string) *Session {
	st.mu.Lock()
	defer st.mu.Unlock()
	if s, ok := st.m[id]; ok {
		s.touch()
		return s
	}
	s := &Session{m: map[string]string{}, lastAccess: time.Now()}
	st.m[id] = s
	return s
}

func (st *Store) cleanupLoop() {
	ticker := time.NewTicker(st.cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		st.cleanupExpired()
	}
}

func (st *Store) cleanupExpired() {
	expiredBefore := time.Now().Add(-st.ttl)
	st.mu.Lock()
	defer st.mu.Unlock()
	for id, sess := range st.m {
		if sess.LastAccess().Before(expiredBefore) {
			delete(st.m, id)
		}
	}
}

func Must(c *gin.Context) *Session {
	v, ok := c.Get("sess")
	if !ok {
		panic("session missing")
	}
	return v.(*Session)
}
