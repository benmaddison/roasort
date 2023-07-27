use std::collections::BTreeMap;

use anyhow::Context;

pub mod cli;

mod ir;
use ir::RoaPrefixRange;

fn collect<S, I, E>(iter: I) -> anyhow::Result<BTreeMap<RoaPrefixRange, usize>>
where
    S: AsRef<str>,
    I: IntoIterator<Item = Result<S, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    iter.into_iter()
        .enumerate()
        .map(|(i, line)| {
            Ok((
                line.context("failed to get input line")?.as_ref().parse()?,
                i,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering() -> anyhow::Result<()> {
        let input = vec![
            Ok::<_, std::io::Error>("10.0.0.0/24"),
            Ok("10.0.0.0/24-24"),
            Ok("10.0.0.0/8"),
            Ok("2001:db8:db8::/48"),
            Ok("2001:db8::/32"),
        ];
        let expect = vec![
            "10.0.0.0/8",
            "10.0.0.0/24",
            "2001:db8::/32",
            "2001:db8:db8::/48",
        ];
        let mut errs = 0usize;
        let output: Vec<_> = collect(input)?
            .into_iter()
            .enumerate()
            .map(|(i, (item, j))| {
                if i != j {
                    errs += 1;
                };
                if item.has_explicit_equal_max_length() {
                    errs += 1;
                }
                item.to_string()
            })
            .collect();
        assert_eq!(output, expect);
        assert_eq!(errs, 3);
        Ok(())
    }
}
