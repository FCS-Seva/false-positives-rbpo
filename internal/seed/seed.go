package seed

import (
	"context"
	"database/sql"

	"github.com/FCS-Seva/false-positives-rbpo/internal/password"
	"github.com/FCS-Seva/false-positives-rbpo/migrations"
)

func Apply(ctx context.Context, db *sql.DB, secret string) error {
	if err := migrations.Apply(ctx, db); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, a := range []struct{ login, role string }{{"requester_a", "requester"}, {"requester_b", "requester"}, {"specialist_1", "specialist"}, {"specialist_2", "specialist"}} {
		hash, err := password.Hash(secret)
		if err != nil {
			return err
		}
		var id int64
		if err := tx.QueryRowContext(ctx, `INSERT INTO accounts(login,password_hash,role) VALUES($1,$2,$3) ON CONFLICT(login) DO UPDATE SET password_hash=EXCLUDED.password_hash,role=EXCLUDED.role RETURNING id`, a.login, hash, a.role).Scan(&id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE account_id=$1", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
