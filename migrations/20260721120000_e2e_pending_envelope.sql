-- Deferred DM: server persists opaque pending-message metadata and per-device
-- recipient envelopes appended later by an online sender device. Server never
-- receives or stores an unwrapped content key.

create table e2e_pending_message
(
    mid          integer primary key not null,
    sender_uid   integer   not null,
    target_uid   integer   not null,
    completed_at timestamp,
    created_at   timestamp not null default current_timestamp,
    foreign key (sender_uid) references user (uid) on delete cascade,
    foreign key (target_uid) references user (uid) on delete cascade
);

create index e2e_pending_message_target_idx on e2e_pending_message (target_uid, completed_at);
create index e2e_pending_message_sender_idx on e2e_pending_message (sender_uid, target_uid, completed_at);

create table e2e_pending_envelope
(
    id            integer primary key autoincrement not null,
    mid           integer   not null,
    recipient_uid integer   not null,
    device_id     text      not null,
    envelope      text      not null,
    created_at    timestamp not null default current_timestamp,
    unique (mid, recipient_uid, device_id),
    foreign key (mid) references e2e_pending_message (mid) on delete cascade,
    foreign key (recipient_uid) references user (uid) on delete cascade
);

create index e2e_pending_envelope_mid_idx on e2e_pending_envelope (mid);
