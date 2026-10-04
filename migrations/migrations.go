package migrations

import (
	"context"
	"database/sql"
	_ "embed"
)

//go:embed 001_initial.sql
var initial string

func Apply(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, initial); err != nil {
		return err
	}
	return tx.Commit()
}
