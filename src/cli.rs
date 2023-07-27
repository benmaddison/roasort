use std::{
    fmt,
    fs::File,
    io::{stdin, BufRead, BufReader, Lines},
    path::PathBuf,
    str::FromStr,
};

use anyhow::Context;
use clap::Parser;

use crate::collect;

pub fn main() -> anyhow::Result<()> {
    let mut ret = Ok(());
    let args = Cli::parse();
    let input = args.input.lines()?;
    collect(input)?
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

const ABOUT: &str = "
A utility to read a list of ROA IP address information elements and
then sort and de-duplicate the elements according to the canonicalization
process described in `draft-ietf-sidrops-rfc6482bis`.
";

/// Order and deduplicate ROA IP address information.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = ABOUT)]
struct Cli {
    /// Path to input data file
    #[arg(default_value_t = Input::StdIn)]
    input: Input,
}

#[derive(Debug, Clone)]
enum Input {
    StdIn,
    File(PathBuf),
}

impl Input {
    fn lines(self) -> anyhow::Result<Lines<Box<dyn BufRead>>> {
        let reader: Box<dyn BufRead> = match self {
            Self::StdIn => Box::new(stdin().lock()),
            Self::File(path) => {
                let file = File::open(path)?;
                Box::new(BufReader::new(file))
            }
        };
        Ok(reader.lines())
    }
}

impl fmt::Display for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StdIn => write!(f, "STDIN"),
            Self::File(path) => path.to_string_lossy().fmt(f),
        }
    }
}

impl FromStr for Input {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "-" {
            Ok(Self::StdIn)
        } else {
            s.parse()
                .map(Self::File)
                .context("failed to parse input file path")
        }
    }
}
