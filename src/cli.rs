use std::io::stdin;

use crate::collect;

pub fn main() -> anyhow::Result<()> {
    let mut ret = Ok(());
    collect(stdin().lines())?
        .into_iter()
        .enumerate()
        .for_each(|(i, (item, j))| {
            if i != j {
                ret = Err(anyhow::anyhow!("input was mis-ordered"))
            }
            if item.has_explicit_equal_max_length() {
                ret = Err(anyhow::anyhow!(
                    "item {item} has unnecessarily specified max_length"
                ))
            }
            println!("{item}")
        });
    ret
}
