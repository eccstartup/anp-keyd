ALTER TABLE keys ADD COLUMN document_digest TEXT NOT NULL DEFAULT '';
UPDATE keys SET role='unclassified', generation=generation+1;
CREATE TABLE file_operations (
 operation_id TEXT PRIMARY KEY REFERENCES admin_operations(operation_id),
 vault_id TEXT NOT NULL REFERENCES vaults(vault_id), did TEXT NOT NULL,
 before_digest TEXT NOT NULL, after_digest TEXT NOT NULL, document BLOB NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','complete'))
) STRICT;
CREATE TABLE service_meta_v2 (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL CHECK(schema_version=2),
 instance_id TEXT NOT NULL, boot_epoch INTEGER NOT NULL CHECK(boot_epoch>=0),
 mutation_epoch INTEGER NOT NULL CHECK(mutation_epoch>=0)
) STRICT;
INSERT INTO service_meta_v2 SELECT singleton,2,instance_id,boot_epoch,mutation_epoch FROM service_meta;
DROP TABLE service_meta;
ALTER TABLE service_meta_v2 RENAME TO service_meta;
PRAGMA user_version=2;
