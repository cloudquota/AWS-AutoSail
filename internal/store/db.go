package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/crypto/bcrypt"
)

type Store struct {
	path string
	db   *sql.DB
}

type User struct {
	ID           int64
	Username     string
	PasswordHash string
}

type Key struct {
	ID        int64
	UserID    int64
	Name      string
	AccessKey string
	SecretKey string
	Proxy     string
	CreatedAt time.Time
}

func NewSQLiteStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &Store{path: path, db: db}
	if err := s.initSchema(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) initSchema(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			access_key TEXT NOT NULL,
			secret_key TEXT NOT NULL,
			proxy TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);`,
	}
	for _, q := range queries {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) EnsureUser(username, password string) (bool, error) {
	ctx := context.Background()
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if username == "" || password == "" {
		return false, errors.New("username/password required")
	}
	selectStmt, err := s.db.PrepareContext(ctx, `SELECT id FROM users WHERE username = ? LIMIT 1;`)
	if err != nil {
		return false, err
	}
	defer selectStmt.Close()
	var existingID int64
	err = selectStmt.QueryRowContext(ctx, username).Scan(&existingID)
	if err == nil {
		return false, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}
	insertStmt, err := s.db.PrepareContext(ctx, `INSERT INTO users (username, password_hash) VALUES (?, ?);`)
	if err != nil {
		return false, err
	}
	defer insertStmt.Close()
	_, err = insertStmt.ExecContext(ctx, username, string(hash))
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if username == "" || password == "" {
		return nil, errors.New("missing credentials")
	}
	stmt, err := s.db.PrepareContext(ctx, `SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1;`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	u := &User{}
	if err := stmt.QueryRowContext(ctx, username).Scan(&u.ID, &u.Username, &u.PasswordHash); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return nil, errors.New("invalid password")
	}
	return u, nil
}

func (s *Store) ListKeys(ctx context.Context, userID int64) ([]Key, error) {
	stmt, err := s.db.PrepareContext(ctx, `SELECT id, user_id, name, access_key, secret_key, proxy, created_at FROM api_keys WHERE user_id = ? ORDER BY id DESC;`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		var (
			key          Key
			createdAtRaw string
		)
		if err := rows.Scan(&key.ID, &key.UserID, &key.Name, &key.AccessKey, &key.SecretKey, &key.Proxy, &createdAtRaw); err != nil {
			return nil, err
		}
		key.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAtRaw)
		out = append(out, Key{
			ID:        key.ID,
			UserID:    key.UserID,
			Name:      key.Name,
			AccessKey: key.AccessKey,
			SecretKey: key.SecretKey,
			Proxy:     key.Proxy,
			CreatedAt: key.CreatedAt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) CreateKey(ctx context.Context, userID int64, name, accessKey, secretKey, proxy string) (int64, error) {
	if strings.TrimSpace(accessKey) == "" || strings.TrimSpace(secretKey) == "" {
		return 0, errors.New("missing key values")
	}
	if strings.TrimSpace(name) == "" {
		name = time.Now().Format("2006-01-02 15:04")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	insertStmt, err := tx.PrepareContext(ctx, `INSERT INTO api_keys (user_id, name, access_key, secret_key, proxy) VALUES (?, ?, ?, ?, ?);`)
	if err != nil {
		return 0, err
	}
	defer insertStmt.Close()
	if _, err = insertStmt.ExecContext(ctx, userID, name, accessKey, secretKey, proxy); err != nil {
		return 0, err
	}
	var insertID int64
	if err = tx.QueryRowContext(ctx, `SELECT last_insert_rowid();`).Scan(&insertID); err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return insertID, nil
}

func (s *Store) DeleteKey(ctx context.Context, userID, keyID int64) error {
	if keyID == 0 {
		return nil
	}
	stmt, err := s.db.PrepareContext(ctx, `DELETE FROM api_keys WHERE id = ? AND user_id = ?;`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, keyID, userID)
	return err
}

func (s *Store) UpdateKey(ctx context.Context, userID, keyID int64, name, accessKey, secretKey, proxy string) error {
	if keyID == 0 {
		return errors.New("missing key id")
	}
	if strings.TrimSpace(accessKey) == "" || strings.TrimSpace(secretKey) == "" {
		return errors.New("missing key values")
	}
	if strings.TrimSpace(name) == "" {
		name = time.Now().Format("2006-01-02 15:04")
	}
	stmt, err := s.db.PrepareContext(ctx, `UPDATE api_keys SET name = ?, access_key = ?, secret_key = ?, proxy = ? WHERE id = ? AND user_id = ?;`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, name, accessKey, secretKey, proxy, keyID, userID)
	return err
}
