// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

/*
 * Amass Engine allow users to create multiple sessions.
 * Each session has its own configuration.
 * The session manager is responsible for managing all sessions,
 * it's a singleton object and it's thread-safe.
 */

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v4/config"
	et "github.com/owasp-amass/amass/v4/engine/types"
)

type manager struct {
	sync.RWMutex
	logger   *slog.Logger
	redis    *redis.Client
	sessions map[uuid.UUID]*Session
}

// NewManager: creates a new session storage.
func NewManager(l *slog.Logger) et.SessionManager {
	redisAddr := os.Getenv("REDIS_ADDR")
	redisPassword := os.Getenv("REDIS_PASSWORD")

	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       0, // use default DB
	})

	return &manager{
		logger:   l,
		redis:    redisClient,
		sessions: make(map[uuid.UUID]*Session),
	}
}

func (r *manager) NewSession(cfg *config.Config) (et.Session, error) {
	s, err := NewSession(cfg, r.redis)
	if err != nil {
		return nil, err
	}
	if err := s.Save(); err != nil {
		return nil, err
	}
	r.Lock()
	r.sessions[s.ID()] = s
	r.Unlock()
	return s, nil
}

// Add: adds a session to a session storage after checking the session config.
func (r *manager) AddSession(s et.Session) (uuid.UUID, error) {
	if s == nil {
		return uuid.UUID{}, nil
	}

	r.Lock()
	defer r.Unlock()

	var id uuid.UUID
	if sess, ok := s.(*Session); ok {
		id = sess.id
		r.sessions[id] = sess
	}
	// TODO: Need to add the session config checks here (using the Registry)
	return id, nil
}

// CancelSession: cancels a session in a session storage.
func (r *manager) CancelSession(id uuid.UUID) {
	s := r.GetSession(id)
	if s == nil {
		return
	}
	s.Kill()
	s.Delete()

	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	for range t.C {
		ss := s.Stats()
		ss.Lock()
		if ss.WorkItemsTotal == ss.WorkItemsCompleted {
			ss.Unlock()
			break
		}
		ss.Unlock()
	}

	r.Lock()
	defer r.Unlock()

	if c := r.sessions[id].Cache(); c != nil {
		c.Close()
	}
	if dir := r.sessions[id].TmpDir(); dir != "" {
		os.RemoveAll(dir)
	}
	if db := s.DB(); db != nil {
		if err := db.Close(); err != nil {
			s.Log().Error(fmt.Sprintf("failed to close the database for session %s: %v", id, err))
		}
	}
	if set := s.EventSet(); set != nil {
		set.Close()
	}
	delete(r.sessions, id)
}

// GetSession: returns a session from a session storage.
func (r *manager) GetSession(id uuid.UUID) et.Session {
	r.RLock()
	defer r.RUnlock()

	if s, found := r.sessions[id]; found {
		return s
	}
	return nil
}

// Shutdown: cleans all sessions from a session storage and shutdown the session storage.
func (r *manager) Shutdown() {
	r.Lock()
	defer r.Unlock()

	for id, s := range r.sessions {
		s.Kill()
		s.Delete()
		delete(r.sessions, id)
	}
}
