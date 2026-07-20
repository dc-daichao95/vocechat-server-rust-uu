alter table e2e_backup add column version integer not null default 2;
alter table e2e_backup add column size_bytes integer not null default 0;
alter table e2e_backup add column updated_by_device text not null default '';
