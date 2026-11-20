// SPDX-License-Identifier: AGPL-3.0-or-later

package publictls

import (
	"context"
	"log/slog"
	"slices"
	"strings"

	"go.uber.org/zap/zapcore"
)

// slogCore sends certmagic's zap log to varlatchd's slog log. certmagic's
// debug and info lines (locks, solvers, every step of an order) are
// debug here; its warnings and errors are info, since this package logs
// each attempt's outcome itself, at info or warn.
type slogCore struct {
	log    *slog.Logger
	fields []zapcore.Field
}

func newSlogCore(log *slog.Logger) zapcore.Core { return &slogCore{log: log} }

func level(l zapcore.Level) slog.Level {
	if l >= zapcore.WarnLevel {
		return slog.LevelInfo
	}
	return slog.LevelDebug
}

func (c *slogCore) Enabled(l zapcore.Level) bool {
	return c.log.Enabled(context.Background(), level(l))
}

func (c *slogCore) With(fields []zapcore.Field) zapcore.Core {
	return &slogCore{log: c.log, fields: append(slices.Clone(c.fields), fields...)}
}

func (c *slogCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c *slogCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, f := range append(slices.Clone(c.fields), fields...) {
		f.AddTo(enc)
	}
	keys := make([]string, 0, len(enc.Fields))
	for k := range enc.Fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	args := make([]any, 0, 2*len(keys)+2)
	if e.LoggerName != "" {
		args = append(args, "logger", e.LoggerName)
	}
	for _, k := range keys {
		args = append(args, k, enc.Fields[k])
	}
	c.log.Log(context.Background(), level(e.Level), strings.TrimSpace(e.Message), args...)
	return nil
}

func (c *slogCore) Sync() error { return nil }
