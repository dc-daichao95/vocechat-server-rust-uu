-- Track identity key rotation and device retirement so a completed pending
-- envelope stays tied to the exact identity version it was wrapped for, and
-- a deleted/retired device is never treated as a valid pending recipient.

alter table e2e_identity add column key_version integer not null default 1;
alter table e2e_identity add column retired_at timestamp;

-- SQLite cannot drop a table-level unique constraint in place, so rebuild
-- e2e_pending_envelope with identity_version included in the uniqueness key.
create table e2e_pending_envelope_v2
(
    id               integer primary key autoincrement not null,
    mid              integer   not null,
    recipient_uid    integer   not null,
    device_id        text      not null,
    identity_version integer   not null default 1,
    envelope         text      not null,
    created_at       timestamp not null default current_timestamp,
    unique (mid, recipient_uid, device_id, identity_version),
    foreign key (mid) references e2e_pending_message (mid) on delete cascade,
    foreign key (recipient_uid) references user (uid) on delete cascade
);

insert into e2e_pending_envelope_v2
    (id, mid, recipient_uid, device_id, identity_version, envelope, created_at)
select id, mid, recipient_uid, device_id, 1, envelope, created_at
from e2e_pending_envelope;

drop table e2e_pending_envelope;
alter table e2e_pending_envelope_v2 rename to e2e_pending_envelope;

create index e2e_pending_envelope_mid_idx on e2e_pending_envelope (mid);
