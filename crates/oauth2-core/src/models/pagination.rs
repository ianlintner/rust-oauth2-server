use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDir {
    #[default]
    Desc,
    Asc,
}

impl SortDir {
    pub fn sql_str(&self) -> &'static str {
        match self {
            SortDir::Asc => "ASC",
            SortDir::Desc => "DESC",
        }
    }
}

/// Query parameters accepted by paginated list endpoints.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub sort_by: Option<String>,
    pub sort_dir: Option<SortDir>,
    /// Substring match against name, id, username, or email depending on entity.
    pub search: Option<String>,
    /// Status filter: "active", "revoked", "expired", "pending", "approved", "denied", etc.
    pub status: Option<String>,
}

impl ListQuery {
    pub fn effective_limit(&self) -> u32 {
        self.limit.unwrap_or(25).min(200)
    }

    pub fn effective_offset(&self) -> u32 {
        self.offset.unwrap_or(0)
    }

    /// Returns a LIKE search pattern (`%value%`), or `%` (matches all) if no search.
    pub fn search_pattern(&self) -> String {
        self.search
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|s| format!("%{}%", s.to_lowercase()))
            .unwrap_or_else(|| "%".to_string())
    }

    pub fn sort_dir_sql(&self) -> &'static str {
        self.sort_dir
            .as_ref()
            .map(|d| d.sql_str())
            .unwrap_or("DESC")
    }
}

/// Paginated response envelope returned by admin list endpoints.
#[derive(Debug, Serialize)]
pub struct Page<T: Serialize> {
    pub items: Vec<T>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

impl<T: Serialize> Page<T> {
    pub fn new(items: Vec<T>, total: u64, limit: u32, offset: u32) -> Self {
        Self {
            items,
            total,
            limit,
            offset,
        }
    }

    /// Build a Page by applying in-memory paging to an already-sorted vec.
    pub fn from_vec(all: Vec<T>, q: &ListQuery) -> Self {
        let limit = q.effective_limit();
        let offset = q.effective_offset();
        let total = all.len() as u64;
        let items = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Self::new(items, total, limit, offset)
    }
}
