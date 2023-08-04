use std::{
    fmt,
    fs::File,
    io::{stdin, BufRead, BufReader},
    path::PathBuf,
    str::FromStr,
};

use anyhow::Context;

use clap::{Parser, ValueEnum};

use clap_verbosity_flag::Verbosity;

use simple_logger::SimpleLogger;

use crate::ir::RoaPrefixRanges;

/// Entry-point for `roasort` application.
#[allow(clippy::missing_errors_doc)]
pub fn main() -> anyhow::Result<()> {
    let mut ret = Ok(());
    let args = Cli::parse();
    SimpleLogger::new()
        .with_level(args.verbosity.log_level_filter())
        .init()?;
    let input = args.input.reader()?;
    args.input_type
        .read(input)?
        .into_iter()
        .enumerate()
        .for_each(|(i, (item, j))| {
            if i != j {
                ret = Err(anyhow::anyhow!("input was mis-ordered"));
            }
            if item.has_explicit_equal_max_length() {
                ret = Err(anyhow::anyhow!(
                    "item {item} has unnecessarily specified max_length"
                ));
            }
            println!("{item}");
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

    /// Input type
    #[arg(long, short = 't', value_enum, default_value_t = InputType::Text)]
    input_type: InputType,

    #[command(flatten)]
    verbosity: Verbosity,
}

#[derive(Debug, Clone)]
enum Input {
    StdIn,
    File(PathBuf),
}

impl Input {
    fn reader(self) -> anyhow::Result<Box<dyn BufRead>> {
        log::info!("opening input");
        let reader: Box<dyn BufRead> = match self {
            Self::StdIn => Box::new(stdin().lock()),
            Self::File(path) => {
                log::info!("trying to open {}", path.display());
                let file = File::open(path)?;
                Box::new(BufReader::new(file))
            }
        };
        Ok(reader)
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
        if s == "-" || s == "STDIN" {
            Ok(Self::StdIn)
        } else {
            s.parse()
                .map(Self::File)
                .context("failed to parse input file path")
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InputType {
    Text,
    Roa,
}

impl InputType {
    fn read<R: BufRead>(self, mut reader: R) -> anyhow::Result<RoaPrefixRanges> {
        match self {
            Self::Text => RoaPrefixRanges::from_text(reader.lines()),
            Self::Roa => {
                let mut buf = Vec::new();
                log::info!("reading input");
                _ = reader.read_to_end(&mut buf)?;
                RoaPrefixRanges::from_roa(&buf)
            }
        }
    }
}
