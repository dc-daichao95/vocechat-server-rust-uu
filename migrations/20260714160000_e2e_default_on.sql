-- Default E2E ON for all communications (uu e2e_ver=1).
-- Existing sessions: enable unless operators later opt out via API/UI.

update `group` set e2e_enabled = 1 where e2e_enabled = 0;

-- SQLite cannot ALTER COLUMN default easily; new inserts set e2e_enabled explicitly in code.
-- Ensure DM table default matches product intent for any future raw inserts:
-- (existing missing rows are treated as enabled in API get_dm_setting)

insert into e2e_dm_setting (uid_low, uid_high, e2e_enabled, updated_at)
select u1.uid, u2.uid, 1, current_timestamp
from user u1
join user u2 on u1.uid < u2.uid
where not exists (
  select 1 from e2e_dm_setting s
  where s.uid_low = u1.uid and s.uid_high = u2.uid
);
