//! `convert`: DAV captures into a scenario.

use std::io::Write;

use davhaven_testkit::convert::{Options, convert as convert_captures, read_captures};

use crate::RunnerError;
use crate::cli::ConvertArgs;

/// Converts the captures of a directory and writes the scenario to a new file or to `out`.
pub(crate) fn convert(args: &ConvertArgs, out: &mut dyn Write) -> Result<bool, RunnerError> {
    let exchanges = read_captures(&args.captures)?;
    let converted = convert_captures(
        &exchanges,
        &Options {
            name: args.name.clone(),
            description: args.description.clone(),
            client: args.client.clone(),
            feature: args.feature.clone(),
            provenance: args.provenance.clone(),
            actor: args.actor,
            login_domain: args.login_domain.clone(),
            keep_text: args.keep_text,
        },
    )?;
    match &args.out {
        None => out.write_all(converted.yaml.as_bytes())?,
        Some(path) => {
            // An existing file is never overwritten: a scenario in the repository is reviewed, not regenerated.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|error| RunnerError::File {
                    path: path.display().to_string(),
                    reason: error.to_string(),
                })?;
            file.write_all(converted.yaml.as_bytes())
                .map_err(|error| RunnerError::File {
                    path: path.display().to_string(),
                    reason: error.to_string(),
                })?;
            writeln!(
                out,
                "wrote {} ({} steps from {} exchanges)",
                path.display(),
                converted.scenario.steps.len(),
                exchanges.len()
            )?;
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;

    use crate::scratch::Scratch;

    fn args(captures: PathBuf, out: Option<PathBuf>) -> ConvertArgs {
        ConvertArgs {
            captures,
            name: "captured-list".to_owned(),
            client: "thunderbird".to_owned(),
            feature: "crud".to_owned(),
            provenance: "Thunderbird 128".to_owned(),
            description: None,
            login_domain: None,
            actor: None,
            keep_text: false,
            out,
        }
    }

    fn write_capture(dir: &std::path::Path) {
        let capture = json!({"schema_version": 1, "captured_at": "2027-03-01T10:15:30.123Z", "tenant": "r1-a",
            "request": {"method": "PROPFIND", "path": "/dav/calendars/r1-a/olivia/personal/", "query": null,
                "headers": [["depth", "0"], ["authorization", "<redacted>"]], "body": null},
            "response": {"status": 207, "headers": [["content-type", "application/xml"]],
                "body": "<multistatus xmlns=\"DAV:\"><response><href>/dav/calendars/r1-a/olivia/personal/</href><propstat><prop/><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>"}});
        std::fs::write(dir.join("0001-PROPFIND-207.json"), capture.to_string()).unwrap();
    }

    #[test]
    fn a_capture_directory_becomes_a_scenario_on_standard_output() {
        let scratch = Scratch::new("stdout");
        write_capture(&scratch.0);
        let mut printed = Vec::new();
        assert!(convert(&args(scratch.0.clone(), None), &mut printed).unwrap());
        let yaml = String::from_utf8(printed).unwrap();
        assert!(
            yaml.contains("origin: captured") && yaml.contains("{{tenant}}"),
            "{yaml}"
        );
        assert!(!yaml.contains("r1-a"), "{yaml}");
    }

    #[test]
    fn the_scenario_is_written_to_a_new_file_and_never_over_an_old_one() {
        let scratch = Scratch::new("file");
        write_capture(&scratch.0);
        let target = scratch.0.join("out").with_extension("yaml");
        let mut report = Vec::new();
        assert!(convert(&args(scratch.0.clone(), Some(target.clone())), &mut report).unwrap());
        assert!(String::from_utf8(report).unwrap().starts_with("wrote "));
        let written = std::fs::read_to_string(&target).unwrap();
        assert!(davhaven_testkit::Scenario::from_yaml(&written).is_ok());
        let again = convert(&args(scratch.0.clone(), Some(target)), &mut Vec::new());
        assert!(
            matches!(again, Err(RunnerError::File { .. })),
            "an existing file is never overwritten"
        );
    }

    #[test]
    fn a_directory_without_captures_is_a_runner_error() {
        let scratch = Scratch::new("empty");
        assert!(matches!(
            convert(&args(scratch.0.clone(), None), &mut Vec::new()),
            Err(RunnerError::Convert(_))
        ));
    }
}
