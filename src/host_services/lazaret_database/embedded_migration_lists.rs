pub struct EmbeddedMigration {
    pub migration_name: &'static str,
    pub migration_sql: &'static str,
}

pub const LAZARET_MIGRATIONS: &[EmbeddedMigration] = &[EmbeddedMigration {
    migration_name: "0001_baseline",
    migration_sql: include_str!("../../../migrations/0001_baseline.sql"),
}];
