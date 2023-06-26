package hashcash

import (
	"database/sql"
	"os"
	"os/user"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

const (
	sqlCreateTable = "CREATE TABLE IF NOT EXISTS spent (creation_date TEXT NOT NULL, hashcash TEXT NOT NULL);"
	sqlAddHash     = "INSERT INTO spent VALUES (DATETIME('now', 'localtime'), ?);"
	sqlHashExists  = "SELECT hashcash FROM spent WHERE hashcash = ?;"
)

// DB instance
type DB struct {
	name string
}

// Add a new hashcash entry to the database
func (d *DB) Add(hash string) error {
	db, err := sql.Open("sqlite3", d.name)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(sqlAddHash, hash)
	if err != nil {
		return err
	}
	return nil
}

// Spent checks if a hashcash entry already exists in the database
func (d *DB) Spent(hash string) bool {
	db, err := sql.Open("sqlite3", d.name)
	if err != nil {
		return false
	}
	defer db.Close()
	rows, err := db.Query(sqlHashExists, hash)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		err = rows.Scan(&s)
		if err != nil {
			return false
		}
	}
	return false
}

// exists determines a path/file exists
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// createDBFile creates a new sqlite3 database file
func createDBFile(path string) error {
	_, err := os.Create(path)
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(sqlCreateTable)
	if err != nil {
		return err
	}
	return nil
}

// NewSQLite3DB creates a new DB Storage instance.
func NewSQLite3DB() (Storage, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	var (
		dbName  = "spent.db"
		dirName = ".hashcash"
		path    = filepath.Join(u.HomeDir, dirName)
	)
	created, err := exists(path)
	if err != nil {
		return nil, err
	}
	if !created {
		err := os.MkdirAll(path, os.ModePerm)
		if err != nil {
			return nil, err
		}
	}
	path = filepath.Join(path, dbName)
	created, err = exists(path)
	if err != nil {
		return nil, err
	}
	if !created {
		err := createDBFile(path)
		if err != nil {
			return nil, err
		}
	}
	return &DB{name: path}, nil
}
