-- Opaque RFC 9420 delivery state. The server never parses MLS artifacts.

create table mls_device
(
    uid         integer   not null,
    device_id   text      not null,
    credential  blob      not null,
    updated_at  timestamp not null default current_timestamp,
    primary key (uid, device_id),
    foreign key (uid) references user (uid) on delete cascade
);

create table mls_key_package
(
    id          integer primary key autoincrement not null,
    uid         integer   not null,
    device_id   text      not null,
    package     blob      not null,
    consumed_at timestamp,
    created_at  timestamp not null default current_timestamp,
    foreign key (uid, device_id) references mls_device (uid, device_id) on delete cascade
);

create index mls_key_package_available
    on mls_key_package (uid, device_id, consumed_at, id);

create table mls_route
(
    token               text primary key not null,
    gid                 integer unique not null,
    membership_revision integer not null default 0,
    initializer_uid      integer,
    initializer_device   text,
    initializer_lease    timestamp,
    initialized          boolean not null default false,
    created_at          timestamp not null default current_timestamp,
    foreign key (gid) references `group` (gid) on delete cascade
);

create table mls_artifact
(
    sequence    integer primary key autoincrement not null,
    route_token text      not null,
    sender_uid  integer   not null,
    device_id   text      not null,
    payload     blob      not null,
    created_at  timestamp not null default current_timestamp,
    foreign key (route_token) references mls_route (token) on delete cascade,
    foreign key (sender_uid, device_id) references mls_device (uid, device_id) on delete restrict
);

create index mls_artifact_route_sequence
    on mls_artifact (route_token, sequence);

create table protocol_generation
(
    singleton  integer primary key check (singleton = 1),
    generation integer not null check (generation = 2),
    cutover_at timestamp
);

insert into protocol_generation (singleton, generation) values (1, 2);
