-- E2E: identity keys, prekeys, encrypted backup, session flags
-- Server stores only public material and opaque blobs; never private keys.

create table e2e_identity
(
    uid               integer   not null,
    device_id         text      not null,
    identity_key_pub  text      not null,
    signed_prekey_pub text,
    signed_prekey_sig text,
    updated_at        timestamp not null default current_timestamp,
    primary key (uid, device_id),
    foreign key (uid) references user (uid) on delete cascade
);

create table e2e_prekey
(
    id         integer primary key autoincrement not null,
    uid        integer   not null,
    device_id  text      not null,
    key_id     integer   not null,
    public_key text      not null,
    consumed   boolean   not null default false,
    created_at timestamp not null default current_timestamp,
    unique (uid, device_id, key_id),
    foreign key (uid) references user (uid) on delete cascade
);

create table e2e_backup
(
    uid        integer primary key not null,
    blob       blob                not null,
    updated_at timestamp           not null default current_timestamp,
    foreign key (uid) references user (uid) on delete cascade
);

-- DM pair: uid_low < uid_high
create table e2e_dm_setting
(
    uid_low      integer not null,
    uid_high     integer not null,
    e2e_enabled  boolean not null default false,
    updated_at   timestamp not null default current_timestamp,
    primary key (uid_low, uid_high),
    foreign key (uid_low) references user (uid) on delete cascade,
    foreign key (uid_high) references user (uid) on delete cascade
);

alter table `group` add column e2e_enabled boolean not null default false;
