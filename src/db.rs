use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn create_pool(database_url: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(8)
        .min_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .idle_timeout(std::time::Duration::from_secs(600))
        .connect(database_url)
        .await
        .expect("Failed to connect to PostgreSQL")
}

pub async fn run_migrations(pool: &PgPool) {
    sqlx::raw_sql(include_str!("../migrations/001_initial_schema.sql"))
        .execute(pool)
        .await
        .expect("Failed to run migration 001");

    sqlx::raw_sql(include_str!("../migrations/002_manage_guild.sql"))
        .execute(pool)
        .await
        .expect("Failed to run migration 002");

    sqlx::raw_sql(include_str!("../migrations/003_user_guilds_discord_username.sql"))
        .execute(pool)
        .await
        .expect("Failed to run migration 003");

    sqlx::raw_sql(include_str!("../migrations/004_oauth_states_silent.sql"))
        .execute(pool)
        .await
        .expect("Failed to run migration 004");

    sqlx::raw_sql(include_str!("../migrations/005_user_guild_optouts.sql"))
        .execute(pool)
        .await
        .expect("Failed to run migration 005");

    sqlx::raw_sql(include_str!("../migrations/006_user_settings.sql"))
        .execute(pool)
        .await
        .expect("Failed to run migration 006");

    sqlx::raw_sql(include_str!("../migrations/007_user_guilds_icon.sql"))
        .execute(pool)
        .await
        .expect("Failed to run migration 007");

    sqlx::raw_sql(include_str!("../migrations/008_auto_enable_default_false.sql"))
        .execute(pool)
        .await
        .expect("Failed to run migration 008");

    sqlx::raw_sql(include_str!("../migrations/009_cleanup_removed_plugins.sql"))
        .execute(pool)
        .await
        .expect("Failed to run migration 009");
}
