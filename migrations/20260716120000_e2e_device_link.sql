-- E2E Phase C: short-lived device-link pairing (opaque package only; no private keys in clear).

create table e2e_device_link
(
    id            integer primary key autoincrement not null,
    uid           integer   not null,
    token         text      not null unique,
    package_blob  blob,
    created_at    timestamp not null default current_timestamp,
    expires_at    timestamp not null,
    consumed_at   timestamp,
    foreign key (uid) references user (uid) on delete cascade
);

create index e2e_device_link_uid_idx on e2e_device_link (uid);
create index e2e_device_link_expires_idx on e2e_device_link (expires_at);
