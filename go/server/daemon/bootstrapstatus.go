// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/varlatch/varlatch/go/server/config"
)

// `varlatchd admin bootstrap-status` (the TypeScript server's, cli.ts;
// ADR-0035 D7): read-only, what `varlatch setup` needs to wait for the
// first administrator and to resume after an interrupted enrollment:
//
//	{"initialized":bool,"bootstrapped":bool,"admins":[{"id","enabled","hasPasskey"}]}
//
// It reads the database read-only, beside a running daemon or without
// one, and changes nothing; no key is read. An installation not created
// yet is {"initialized":false,"bootstrapped":false,"admins":[]}.

// BootstrapStatus is the command's answer.
type BootstrapStatus struct {
	Initialized  bool                   `json:"initialized"`
	Bootstrapped bool                   `json:"bootstrapped"`
	Admins       []BootstrapStatusAdmin `json:"admins"`
}

// BootstrapStatusAdmin is one Installation Admin.
type BootstrapStatusAdmin struct {
	ID         string `json:"id"`
	Enabled    bool   `json:"enabled"`
	HasPasskey bool   `json:"hasPasskey"`
}

func bootstrapStatusOf(conn *sql.DB) (BootstrapStatus, error) {
	st := BootstrapStatus{Admins: []BootstrapStatusAdmin{}}
	if conn == nil {
		return st, nil
	}
	var at sql.NullInt64
	switch err := conn.QueryRow("SELECT bootstrapped_at FROM installation LIMIT 1").Scan(&at); {
	case errors.Is(err, sql.ErrNoRows):
		return st, nil
	case err != nil:
		return st, fmt.Errorf("the installation's database cannot be read: %w", err)
	}
	st.Initialized, st.Bootstrapped = true, at.Valid
	rows, err := conn.Query(`SELECT i.id, NOT i.disabled,
		EXISTS (SELECT 1 FROM auth_user_links l JOIN passkeys p ON p.user_id = l.better_auth_user_id WHERE l.identity_id = i.id)
		FROM identities i WHERE i.installation_admin ORDER BY i.created_at, i.id`)
	if err != nil {
		return st, fmt.Errorf("the installation's database cannot be read: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var a BootstrapStatusAdmin
		if err := rows.Scan(&a.ID, &a.Enabled, &a.HasPasskey); err != nil {
			return st, err
		}
		st.Admins = append(st.Admins, a)
	}
	return st, rows.Err()
}

// runBootstrapStatus is `admin bootstrap-status`, read-only.
func runBootstrapStatus(cfg *config.Config, stdout, stderr io.Writer) int {
	conn, err := openReadOnly(cfg)
	if err == nil && conn != nil {
		defer conn.Close()
	}
	var st BootstrapStatus
	if err == nil {
		st, err = bootstrapStatusOf(conn)
	}
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin bootstrap-status: %s\n", err.Error())
		return ExitFailure
	}
	b, err := json.Marshal(st)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd admin bootstrap-status: %s\n", err.Error())
		return ExitFailure
	}
	fmt.Fprintln(stdout, string(b))
	return ExitOK
}
