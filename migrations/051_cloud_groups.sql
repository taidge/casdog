CREATE TABLE syncer_group_links (
    syncer_id TEXT NOT NULL REFERENCES syncers(id) ON DELETE CASCADE,
    source_key TEXT NOT NULL,
    organization TEXT NOT NULL,
    group_id TEXT NOT NULL UNIQUE REFERENCES groups(id) ON DELETE CASCADE,
    group_name TEXT NOT NULL,
    remote_email TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY(syncer_id,source_key)
);
CREATE TABLE syncer_group_memberships (
    syncer_id TEXT NOT NULL,
    source_group_key TEXT NOT NULL,
    source_user_key TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_group_id TEXT REFERENCES user_groups(id) ON DELETE SET NULL,
    group_value TEXT NOT NULL,
    owns_user_group BOOLEAN NOT NULL,
    owns_user_group_value BOOLEAN NOT NULL,
    manual_preserved BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY(syncer_id,source_group_key,user_id),
    FOREIGN KEY(syncer_id,source_group_key) REFERENCES syncer_group_links(syncer_id,source_key) ON DELETE CASCADE
);
CREATE INDEX syncer_group_memberships_pair ON syncer_group_memberships(user_id,group_id);
