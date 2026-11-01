//! `--principal-token-command`: the command of the operator that issues the principal tokens that open MCP.
//!
//! The management API issues the scopes of MCP to a service principal and to nobody else; a user gets them only from the operator,
//! on the host of the instance (`davhaven admin principal-token create`). A run builds its world itself, so it asks for every
//! token after it has made the principal, and the command is how it asks: a shell command with placeholders that the run fills in
//! for each token, which prints the secret of the new token on its standard output and nothing else (that is what
//! `--print-token` does).
//!
//! ```text
//! --principal-token-command 'ssh staging docker exec davhaven davhaven admin principal-token create \
//!     --tenant {tenant} --principal {principal} --label {label} {scopes} --expires-in {expires_in} --print-token'
//! ```
//!
//! * `{tenant}`, `{principal}` and `{label}` are the values of `--tenant`, `--principal` and `--label`;
//! * `{scopes}` is `--scope mcp:read --scope mcp:write ...`, one flag per scope, and `{expires_in}` the lifetime (`1d`).
//!
//! The command line is refused at startup when the command lacks one of the placeholders ([`parse_template`]): without `{scopes}`
//! the tokens would carry the scopes the operator wrote and the one-scope tokens of the matrix would be none, and without `{label}`
//! the second token of a principal would find the first one's label taken and print nothing.
//!
//! Every value that goes into the command is a slug, a label the run makes or the name of a scope, and a value that does not start
//! with a letter or a digit, or has a character outside letters, digits and `-_.:`, is refused, so that nothing a world or an
//! instance contains can become shell syntax or an option of the command. What the command prints is the secret, so it is never
//! shown, not even when it is not what a token looks like: the error says what is wrong with it and nothing of it. What the
//! command writes to its standard error (the report of the command) reaches the terminal as it is.
//!
//! The command runs in a process group of its own and without a terminal to read from: it cannot ask for a passphrase (use a key
//! in an agent, `ssh -o BatchMode=yes`). It has two minutes for each token; when they pass, the whole group is killed, and the
//! run stops with the reason.

use core::time::Duration;
use std::process::Stdio;

use async_trait::async_trait;
use davhaven_testkit::staging::{PrincipalTokenIssuer, PrincipalTokenRequest};
use tokio::io::AsyncReadExt as _;
use tokio::process::{Child, Command};

/// How long one token may take: the command usually connects to the host of the instance and starts the program there.
const LIMIT: Duration = Duration::from_secs(120);

/// What a principal token starts with (PLAN 2.6).
const TOKEN_START: &str = "dvh_pat_";

/// The placeholders a command has to contain: each of them is what a token needs that the command cannot know.
const PLACEHOLDERS: [&str; 5] = ["{tenant}", "{principal}", "{label}", "{scopes}", "{expires_in}"];

/// The value parser of `--principal-token-command`: the command as it was written when it contains every placeholder, and what is
/// missing when it does not. A blank command is no command (the variable of the environment that is set and empty).
///
/// # Errors
///
/// The text for the person who wrote the command: the placeholders it lacks and what each of them does.
pub(crate) fn parse_template(text: &str) -> Result<String, String> {
    if text.trim().is_empty() {
        return Ok(String::new());
    }
    let missing: Vec<&str> = PLACEHOLDERS
        .into_iter()
        .filter(|placeholder| !text.contains(placeholder))
        .collect();
    if missing.is_empty() {
        return Ok(text.to_owned());
    }
    Err(format!(
        "the command has no {}: the run fills in {} for every token (`{{scopes}}` becomes `--scope a --scope b`, `{{expires_in}}` \
         `1d`), and a token made without them would not be the one the run asked for",
        missing.join(", "),
        PLACEHOLDERS.join(", ")
    ))
}

/// Issues principal tokens by running the command the operator gave.
#[derive(Debug, Clone)]
pub(crate) struct CommandIssuer {
    template: String,
    limit: Duration,
}

/// Whether a value may go into a shell command: it starts with a letter or a digit (so that it is no option of the command) and
/// has nothing but letters, digits and `-_.:`.
fn is_safe(value: &str) -> bool {
    value.chars().next().is_some_and(|first| first.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':'))
}

impl CommandIssuer {
    /// An issuer that runs `template`, in which the placeholders are replaced for every token.
    pub(crate) fn new(template: impl Into<String>) -> Self {
        Self {
            template: template.into(),
            limit: LIMIT,
        }
    }

    /// The same issuer with another limit for one token.
    #[cfg(test)]
    fn with_limit(mut self, limit: Duration) -> Self {
        self.limit = limit;
        self
    }

    /// The command for a request: the template with the placeholders replaced.
    ///
    /// # Errors
    ///
    /// The text of the value that cannot go into a shell command.
    fn command_for(&self, request: &PrincipalTokenRequest) -> Result<String, String> {
        let scopes: Vec<&str> = request.scopes.iter().map(|scope| scope.as_str()).collect();
        let values = [
            request.tenant.as_str(),
            request.principal.as_str(),
            request.label.as_str(),
        ]
        .into_iter()
        .chain(scopes.iter().copied());
        for value in values {
            if !is_safe(value) {
                return Err(format!(
                    "the value `{value}` cannot go into a shell command (it starts with a letter or a digit and has letters, \
                     digits and `-_.:`)"
                ));
            }
        }
        let scopes = scopes
            .iter()
            .map(|scope| format!("--scope {scope}"))
            .collect::<Vec<_>>()
            .join(" ");
        Ok(self
            .template
            .replace("{tenant}", request.tenant.as_str())
            .replace("{principal}", request.principal.as_str())
            .replace("{label}", &request.label)
            .replace("{scopes}", &scopes)
            .replace("{expires_in}", &format!("{}d", request.expires_in_days)))
    }
}

/// The secret in what a command printed, or what is wrong with the output (never the output itself: it is a secret).
fn secret_of(stdout: &[u8]) -> Result<String, String> {
    let text = String::from_utf8_lossy(stdout);
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    match (lines.next(), lines.next()) {
        (None, _) => Err(
            "it printed nothing (for example because a token with this label exists already: the command cannot show the secret of \
             a token again)"
                .to_owned(),
        ),
        (Some(_), Some(_)) => Err("it printed more than the secret of the token".to_owned()),
        (Some(secret), None) if !secret.starts_with(TOKEN_START) => Err(format!(
            "what it printed does not start with `{TOKEN_START}`, so it is not a principal token"
        )),
        (Some(secret), None) if secret.contains(char::is_whitespace) => Err(
            "what it printed starts like a principal token and has white space in it, so it is not one".to_owned(),
        ),
        (Some(secret), None) => Ok(secret.to_owned()),
    }
}

/// Starts `sh -c command` without a terminal to read from, in a process group of its own, so that the command and whatever it
/// starts (`ssh`) can be stopped together; the child is killed when its handle is dropped.
fn start(command: &str) -> std::io::Result<Child> {
    let mut shell = Command::new("sh");
    shell
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(unix)]
    shell.process_group(0);
    shell.spawn()
}

/// Stops the command that did not finish: the process group first (the shell runs `ssh` as a process of its own, and killing the
/// shell alone would leave it running, minting a token after the run has taken its world down), then the shell, which is waited
/// for, so that nothing of it is left when this returns.
async fn stop(child: &mut Child) {
    #[cfg(unix)]
    kill_group(child).await;
    drop(child.kill().await);
}

/// Kills the process group of the shell, which has the process id of the shell (`process_group(0)`). `kill` is the one way to
/// signal a group without `unsafe`; when it fails the group is gone already.
#[cfg(unix)]
async fn kill_group(child: &Child) {
    let Some(group) = child.id() else {
        return;
    };
    drop(
        Command::new("kill")
            .args(["-s", "KILL", "--"])
            .arg(format!("-{group}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await,
    );
}

#[async_trait]
impl PrincipalTokenIssuer for CommandIssuer {
    async fn issue(&self, request: &PrincipalTokenRequest) -> Result<String, String> {
        let command = self.command_for(request)?;
        let mut child = start(&command).map_err(|error| format!("it could not be started: {error}"))?;
        let Some(mut stdout) = child.stdout.take() else {
            stop(&mut child).await;
            return Err("it could not be started: there is no standard output to read".to_owned());
        };
        let finished = tokio::time::timeout(self.limit, async {
            let mut printed = Vec::new();
            stdout.read_to_end(&mut printed).await?;
            let status = child.wait().await?;
            Ok::<_, std::io::Error>((status, printed))
        })
        .await;
        match finished {
            Err(_elapsed) => {
                stop(&mut child).await;
                Err(format!("it did not finish within {:?} and was stopped", self.limit))
            }
            Ok(Err(error)) => {
                stop(&mut child).await;
                Err(format!("it could not be waited for: {error}"))
            }
            Ok(Ok((status, _))) if !status.success() => Err(format!("it failed ({status}); its own report is above")),
            Ok(Ok((_, printed))) => secret_of(&printed),
        }
    }
}

#[cfg(test)]
mod tests {
    use davhaven_testkit::davhaven_domain::{PrincipalName, Scope, TenantSlug};

    use super::*;

    fn request() -> PrincipalTokenRequest {
        PrincipalTokenRequest {
            tenant: TenantSlug::parse("r42-a").unwrap(),
            principal: PrincipalName::parse("olivia").unwrap(),
            label: "conformance-principal-token:r42-a:olivia".to_owned(),
            scopes: vec![Scope::McpRead, Scope::McpWrite],
            expires_in_days: 1,
        }
    }

    const COMMAND: &str = "davhaven admin principal-token create --tenant {tenant} --principal {principal} --label {label} \
                           {scopes} --expires-in {expires_in} --print-token";

    #[test]
    fn the_placeholders_become_the_arguments_of_the_command_of_the_operator() {
        let issuer = CommandIssuer::new(COMMAND);
        assert_eq!(
            issuer.command_for(&request()).unwrap(),
            "davhaven admin principal-token create --tenant r42-a --principal olivia \
             --label conformance-principal-token:r42-a:olivia --scope mcp:read --scope mcp:write --expires-in 1d --print-token"
        );
    }

    #[test]
    fn a_command_without_a_placeholder_is_refused_at_startup_and_says_which() {
        assert_eq!(parse_template(COMMAND).unwrap(), COMMAND);
        for missing in PLACEHOLDERS {
            let without = COMMAND.replace(missing, "x");
            let error = parse_template(&without).unwrap_err();
            assert!(error.contains(&format!("no {missing}")), "{missing}: {error}");
        }
        let hard_coded = "ssh staging davhaven admin principal-token create --tenant {tenant} --principal {principal} \
                          --scope mcp:read --expires-in 30d --print-token";
        let error = parse_template(hard_coded).unwrap_err();
        assert!(error.contains("no {label}, {scopes}, {expires_in}:"), "{error}");
        assert_eq!(
            parse_template("  ").unwrap(),
            "",
            "a blank command is no command, as an empty variable of the environment is"
        );
    }

    #[test]
    fn a_value_that_could_be_shell_syntax_or_an_option_is_refused() {
        let issuer = CommandIssuer::new("echo {label}");
        for bad in [
            "a b",
            "a;b",
            "a$(b)",
            "a`b`",
            "a'b",
            "a\"b",
            "a|b",
            "a&b",
            "a\nb",
            "a>b",
            "",
            "a*",
            "--print-token",
            "-x",
            ".hidden",
            ":a",
        ] {
            let mut asked = request();
            asked.label = bad.to_owned();
            let error = issuer.command_for(&asked).unwrap_err();
            assert!(error.contains("cannot go into a shell command"), "{bad:?}: {error}");
        }
        let mut asked = request();
        asked.label = "ok:label_1.x-y".to_owned();
        assert!(issuer.command_for(&asked).is_ok());
    }

    #[test]
    fn only_a_single_principal_token_is_a_secret() {
        assert_eq!(
            secret_of(b"dvh_pat_aaaaaaaaaaaa_bbbb\n").unwrap(),
            "dvh_pat_aaaaaaaaaaaa_bbbb"
        );
        assert_eq!(
            secret_of(b"\n  dvh_pat_a_b  \n\n").unwrap(),
            "dvh_pat_a_b",
            "blank lines and padding are no part of it"
        );
        for (output, said) in [
            (&b""[..], "printed nothing"),
            (b"\n\n", "printed nothing"),
            (b"dvh_pat_a_b\nsecond line\n", "more than the secret"),
            (b"error: no such tenant\n", "does not start with"),
            (b"dvh_feed_a_b\n", "does not start with"),
            (b"dvh_pat_a b\n", "white space"),
        ] {
            let error = secret_of(output).unwrap_err();
            assert!(error.contains(said), "{error}");
            assert!(
                !error.contains("no such tenant") && !error.contains("second line"),
                "the output is never repeated: {error}"
            );
        }
    }

    #[test]
    fn a_command_that_prints_nothing_is_not_said_to_have_found_a_token_with_the_label() {
        let error = secret_of(b"").unwrap_err();
        assert!(error.contains("for example"), "other reasons are possible: {error}");
    }

    #[tokio::test]
    async fn the_command_runs_and_its_standard_output_is_the_secret() {
        let issuer = CommandIssuer::new("echo dvh_pat_{principal}_{tenant}");
        assert_eq!(issuer.issue(&request()).await.unwrap(), "dvh_pat_olivia_r42-a");
    }

    #[tokio::test]
    async fn a_command_that_fails_or_prints_something_else_is_an_error_without_the_output() {
        let failing = CommandIssuer::new("echo dvh_pat_a_b; exit 3");
        let error = failing.issue(&request()).await.unwrap_err();
        assert!(error.contains("it failed") && !error.contains("dvh_pat_a_b"), "{error}");

        let silent = CommandIssuer::new("true");
        assert!(silent.issue(&request()).await.unwrap_err().contains("printed nothing"));

        let chatty = CommandIssuer::new("echo created; echo dvh_pat_a_b");
        assert!(
            chatty
                .issue(&request())
                .await
                .unwrap_err()
                .contains("more than the secret")
        );

        let missing = CommandIssuer::new("this-command-does-not-exist-0f3a");
        assert!(missing.issue(&request()).await.unwrap_err().contains("it failed"));
    }

    /// Whether the process is alive and not a zombie that waits for its parent: what is left of a killed process that nobody has
    /// collected yet is no longer running.
    #[cfg(target_os = "linux")]
    fn is_running(pid: &str) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
            stat.rsplit_once(')')
                .and_then(|(_, rest)| rest.trim_start().chars().next())
                .is_some_and(|state| state != 'Z' && state != 'X')
        })
    }

    /// Runs `script` with a limit of a second, which it exceeds: the issuer has to give up, with the reason, and the process the
    /// script wrote to `pidfile` has to be gone. Returns what the script recorded.
    #[cfg(target_os = "linux")]
    async fn a_command_that_does_not_finish_is_stopped(script: &str, pidfile: &std::path::Path) -> String {
        let issuer = CommandIssuer::new(script).with_limit(Duration::from_secs(1));
        let error = tokio::time::timeout(Duration::from_secs(30), issuer.issue(&request()))
            .await
            .expect("the issuer gives up by itself, and does not wait for the command")
            .unwrap_err();
        assert!(error.contains("did not finish") && error.contains("stopped"), "{error}");
        std::fs::read_to_string(pidfile).unwrap().trim().to_owned()
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_command_that_does_not_finish_is_killed_and_not_left_running() {
        let scratch = crate::scratch::Scratch::new("issuer-limit");
        let pidfile = scratch.0.join("pid");
        let pid = a_command_that_does_not_finish_is_stopped(
            &format!("echo $$ > '{}'; exec sleep 60", pidfile.display()),
            &pidfile,
        )
        .await;
        assert_ne!(pid, "");
        assert!(!is_running(&pid), "the command was waited for and is gone");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn what_the_command_started_is_killed_with_it() {
        // `ssh` is a process of its own that the shell starts: the shell is not the only one that must go.
        let scratch = crate::scratch::Scratch::new("issuer-group");
        let pidfile = scratch.0.join("pid");
        let pid = a_command_that_does_not_finish_is_stopped(
            &format!("sleep 60 & echo $! > '{}'; wait", pidfile.display()),
            &pidfile,
        )
        .await;
        assert_ne!(pid, "");
        // The signal is sent before the issuer returns; the process leaves when it is next scheduled.
        let mut gone = false;
        for _ in 0..200 {
            if !is_running(&pid) {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(gone, "the process of the command is still running");
    }
}
