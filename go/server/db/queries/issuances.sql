-- The certificate issuance count (internal docs/design/go-step6.md
-- decision 16; schema version 2). Every time written is varlatchd's clock,
-- passed in.

-- name: BeginCertificateIssuance :one
INSERT INTO certificate_issuances (name, started_at) VALUES (?, ?) RETURNING id;

-- name: EndCertificateIssuance :exec
UPDATE certificate_issuances SET outcome = ?, ended_at = ? WHERE id = ? AND outcome = 'started';

-- name: CountCertificateIssuances :one
-- The attempts that count: issued, or never ended (a timeout, a crash).
SELECT count(*) AS n, CAST(coalesce(min(started_at), 0) AS INTEGER) AS oldest
FROM certificate_issuances
WHERE name = ? AND started_at >= ? AND outcome IN ('started', 'issued');

-- name: PruneCertificateIssuances :exec
DELETE FROM certificate_issuances WHERE started_at < ?;
