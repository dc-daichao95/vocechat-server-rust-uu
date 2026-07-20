create table e2e_v2_mls_commit (
    gid integer not null,
    epoch integer not null,
    commit_id text not null,
    sender_uid integer not null,
    sender_device_id text not null,
    primary key (gid, epoch),
    unique (gid, commit_id)
);

create table e2e_v2_mls_welcome (
    gid integer not null,
    epoch integer not null,
    commit_id text not null,
    sender_uid integer not null,
    sender_device_id text not null,
    primary key (gid, epoch, commit_id),
    foreign key (gid, epoch) references e2e_v2_mls_commit (gid, epoch)
);

create table e2e_v2_mls_application (
    gid integer not null,
    epoch integer not null,
    sender_uid integer not null,
    sender_device_id text not null,
    generation integer not null,
    primary key (gid, epoch, sender_uid, sender_device_id, generation)
);
