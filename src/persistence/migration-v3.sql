CREATE TABLE grant_deadlines (grant_id TEXT PRIMARY KEY REFERENCES grants(grant_id), monotonic_deadline INTEGER NOT NULL) STRICT;
CREATE TABLE service_meta_v3 (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL CHECK(schema_version=3),
 instance_id TEXT NOT NULL, boot_epoch INTEGER NOT NULL CHECK(boot_epoch>=0), mutation_epoch INTEGER NOT NULL CHECK(mutation_epoch>=0)
) STRICT;
INSERT INTO service_meta_v3 SELECT singleton,3,instance_id,boot_epoch,mutation_epoch FROM service_meta;
DROP TABLE service_meta;
ALTER TABLE service_meta_v3 RENAME TO service_meta;
PRAGMA user_version=3;
