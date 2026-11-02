use super::PgRepository;
use crate::db::error::DbError;
use crate::db::repo::*;
use async_trait::async_trait;
use relay_shared::models::User;

const USER_COLS: &str =
    "id, username, password, admin, token_version, must_change_password, traffic_used, created_at";

// ── UserRepository ──

#[async_trait]
impl UserRepository for PgRepository {
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, DbError> {
        let sql = format!("SELECT {USER_COLS} FROM users WHERE username = $1");
        let user = sqlx::query_as(&sql)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn find_by_id(&self, id: i64) -> Result<Option<User>, DbError> {
        let sql = format!("SELECT {USER_COLS} FROM users WHERE id = $1");
        let user = sqlx::query_as(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(user)
    }

    async fn find_password_by_id(&self, id: i64) -> Result<Option<String>, DbError> {
        let row: Option<(String,)> = sqlx::query_as("SELECT password FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|(p,)| p))
    }

    async fn find_auth_state_by_id(
        &self,
        id: i64,
    ) -> Result<Option<(i64, bool, bool)>, DbError> {
        let row: Option<(i64, bool, bool)> = sqlx::query_as(
            "SELECT token_version, must_change_password, admin FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn is_admin(&self, id: i64) -> Result<bool, DbError> {
        let row: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM users WHERE id = $1 AND admin = TRUE")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }

    async fn exists_by_id(&self, id: i64) -> Result<bool, DbError> {
        let row: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    async fn update_password(&self, id: i64, new_hash: &str) -> Result<u64, DbError> {
        let result = sqlx::query("UPDATE users SET password = $1 WHERE id = $2")
            .bind(new_hash)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn change_own_password(&self, id: i64, new_hash: &str) -> Result<u64, DbError> {
        let result = sqlx::query(
            "UPDATE users SET password = $1, token_version = token_version + 1, \
             must_change_password = FALSE WHERE id = $2",
        )
        .bind(new_hash)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn admin_reset_password(
        &self,
        id: i64,
        new_hash: &str,
        must_change_password: bool,
    ) -> Result<u64, DbError> {
        let result = sqlx::query(
            "UPDATE users SET password = $1, token_version = token_version + 1, \
             must_change_password = $2 WHERE id = $3",
        )
        .bind(new_hash)
        .bind(must_change_password)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn increment_user_traffic(&self, id: i64, delta: i64) -> Result<(), DbError> {
        sqlx::query("UPDATE users SET traffic_used = traffic_used + $1 WHERE id = $2")
            .bind(delta)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn reset_traffic(&self, id: i64) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE users SET traffic_used = 0 WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE forward_rules SET traffic_used = 0 WHERE uid = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn count_placeholder_admin_password(&self) -> Result<i64, DbError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE id = 1 AND password LIKE '$2b$12$PLACEHOLDER%'",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    async fn replace_placeholder_admin_password(&self, hash: &str) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE users SET password = $1, must_change_password = TRUE \
             WHERE id = 1 AND password LIKE '$2b$12$PLACEHOLDER%'",
        )
        .bind(hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
