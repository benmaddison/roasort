use predicates::{
    path::eq_file,
    str::{is_empty, starts_with},
};

const OK_TXT_PATH: &str = "tests/data/ok.txt";
const OK_ROA_PATH: &str = "tests/data/ok.roa";
const ERR_TXT_PATH: &str = "tests/data/err.txt";
const ERR_ROA_PATH: &str = "tests/data/err.roa";
const ERR_MSG: &str = "Error:";

cases! {
    no_input {|mut cmd| {
        Ok(cmd
            .assert()
            .try_success()?
            .try_stdout(is_empty())?
        )
    }}
    well_ordered_text_from_stdin {|mut cmd | {
        Ok(cmd
            .pipe_stdin(OK_TXT_PATH)?
            .assert()
            .try_success()?
            .try_stdout(eq_file(OK_TXT_PATH))?
            .try_stderr(is_empty())?
        )
    }}
    well_ordered_text_from_file {|mut cmd| {
        Ok(cmd
            .arg(OK_TXT_PATH)
            .assert()
            .try_success()?
            .try_stdout(eq_file(OK_TXT_PATH))?
            .try_stderr(is_empty())?
        )
    }}
    mis_ordered_text_from_stdin {|mut cmd | {
        Ok(cmd
            .pipe_stdin(ERR_TXT_PATH)?
            .assert()
            .try_failure()?
            .try_stdout(eq_file(OK_TXT_PATH))?
            .try_stderr(starts_with(ERR_MSG))?
        )
    }}
    mis_ordered_text_from_file {|mut cmd | {
        Ok(cmd
            .arg(ERR_TXT_PATH)
            .assert()
            .try_failure()?
            .try_stdout(eq_file(OK_TXT_PATH))?
            .try_stderr(starts_with(ERR_MSG))?
        )
    }}
    well_ordered_roa_from_stdin {|mut cmd | {
        Ok(cmd
            .args(["-t", "roa"])
            .pipe_stdin(OK_ROA_PATH)?
            .assert()
            .try_success()?
            .try_stdout(eq_file(OK_TXT_PATH))?
            .try_stderr(is_empty())?
        )
    }}
    well_ordered_roa_from_file {|mut cmd| {
        Ok(cmd
            .args(["-t", "roa"])
            .arg(OK_ROA_PATH)
            .assert()
            .try_success()?
            .try_stdout(eq_file(OK_TXT_PATH))?
            .try_stderr(is_empty())?
        )
    }}
    mis_ordered_roa_from_stdin {|mut cmd | {
        Ok(cmd
            .args(["-t", "roa"])
            .pipe_stdin(ERR_ROA_PATH)?
            .assert()
            .try_failure()?
            .try_stdout(eq_file(OK_TXT_PATH))?
            .try_stderr(starts_with(ERR_MSG))?
        )
    }}
    mis_ordered_roa_from_file {|mut cmd | {
        Ok(cmd
            .args(["-t", "roa"])
            .arg(ERR_ROA_PATH)
            .assert()
            .try_failure()?
            .try_stdout(eq_file(OK_TXT_PATH))?
            .try_stderr(starts_with(ERR_MSG))?
        )
    }}
}

macro_rules! cases {
    ( $( $name:ident { $test:expr } )* ) => {
        $(
            #[test]
            fn $name() -> Result<(), Box<dyn std::error::Error>> {
                assert_cmd::cmd::Command::cargo_bin("roasort")
                    .map_err(|err| Box::new(err) as Box<dyn std::error::Error>)
                    .and_then($test)?;
                Ok(())
            }
        )*
    };
}
use cases;
