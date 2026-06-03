//! Shared minimal glob matcher used by `find` and `search`/`grep`.

/// Minimal glob matcher supporting only the `*` wildcard (matches any run,
/// including empty).  Both arguments should already be case-normalised by the
/// caller if a case-insensitive match is desired.
///
/// Two-pointer algorithm with backtracking — linear in practice and free of
/// the catastrophic backtracking that a naive regex translation could incur.
#[must_use]
pub fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn literal_match() {
        assert!(glob_match("ABC", "ABC"));
        assert!(!glob_match("ABC", "ABD"));
    }

    #[test]
    fn star_suffix() {
        assert!(glob_match("*.TXT", "HELLO.TXT"));
        assert!(!glob_match("*.TXT", "HELLO.BIN"));
    }

    #[test]
    fn star_matches_empty() {
        assert!(glob_match("*", ""));
        assert!(glob_match("A*", "A"));
    }

    #[test]
    fn leading_and_middle_star() {
        assert!(glob_match("*MID*", "XXMIDYY"));
        assert!(!glob_match("*MID*", "XXNOPE"));
    }
}
