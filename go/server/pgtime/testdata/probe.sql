-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Each corpus input read as text::timestamptz: microseconds since 2000-01-01 UTC, infinity, -infinity or ERROR <SQLSTATE>, with now() in Unix microseconds (gen-vectors.py).
create or replace function probe(v text, out res text) language plpgsql as $$
declare t timestamptz;
begin
  begin
    t := v::timestamptz;
    res := case when t = 'infinity' then 'infinity' when t = '-infinity' then '-infinity'
      else (extract(epoch from (t - '2000-01-01 00:00:00+00'::timestamptz)) * 1000000)::numeric(40,0)::text end;
  exception when others then res := 'ERROR ' || sqlstate;
  end;
end $$;
\set corpus `cat /tmp/corpus.json`
\t on
\pset format unaligned
select json_build_object('now', (extract(epoch from now()) * 1000000)::numeric(40,0)::text, 'vectors',
  json_agg(json_build_array(v, probe(v)) order by o)) from json_array_elements_text(:'corpus'::json) with ordinality as e(v, o);
