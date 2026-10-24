use clap::{Args, Parser, Subcommand, ValueEnum};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    version,
    about = "Review saved English-language Windows firewall reports",
    long_about = "Review saved English-language output from netsh advfirewall firewall show rule name=all. Reads files only; never changes Windows settings."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Inspect rules and highlight unrestricted enabled inbound allow rules")]
    Inspect {
        #[arg(help = "Saved report (UTF-8 or UTF-16 with a byte order mark)")]
        input: PathBuf,
        #[command(flatten)]
        filters: Filters,
        #[arg(long, value_enum, default_value = "table")]
        format: Format,
    },
    #[command(about = "Compare two reports by unique rule name, including additional rule fields")]
    Compare {
        #[arg(help = "Earlier saved report")]
        before: PathBuf,
        #[arg(help = "Later saved report")]
        after: PathBuf,
        #[arg(long, value_enum, default_value = "table")]
        format: Format,
    },
}

#[derive(Args, Default)]
struct Filters {
    #[arg(help = "Case-insensitive substring of the rule name")]
    #[arg(long)]
    name: Option<String>,
    #[arg(help = "Case-insensitive direction")]
    #[arg(long, value_enum, ignore_case = true)]
    direction: Option<Direction>,
    #[arg(help = "Case-insensitive action")]
    #[arg(long, value_enum, ignore_case = true)]
    action: Option<Action>,
    #[arg(help = "Case-insensitive enabled state")]
    #[arg(long, value_parser = parse_enabled)]
    enabled: Option<bool>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Table,
    Tsv,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Direction {
    #[value(alias = "inbound")]
    In,
    #[value(alias = "outbound")]
    Out,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Action {
    Allow,
    Block,
    Bypass,
}

fn parse_enabled(value: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" | "enabled" => Ok(true),
        "no" | "false" | "disabled" => Ok(false),
        _ => Err(format!(
            "unrecognised enabled state {value:?}; expected Yes/No, true/false or enabled/disabled"
        )),
    }
}

#[derive(Debug, Clone)]
struct Rule {
    name: String,
    enabled: bool,
    direction: Direction,
    action: Action,
    fields: BTreeMap<String, String>,
    line: usize,
}

impl Rule {
    fn highlighted(&self) -> bool {
        self.enabled
            && self.direction == Direction::In
            && self.action == Action::Allow
            && self.fields["remoteip"].eq_ignore_ascii_case("any")
    }

    fn matches(&self, filters: &Filters) -> bool {
        filters
            .name
            .as_ref()
            .is_none_or(|name| self.name.to_lowercase().contains(&name.to_lowercase()))
            && filters.enabled.is_none_or(|value| self.enabled == value)
            && filters
                .direction
                .is_none_or(|value| self.direction == value)
            && filters.action.is_none_or(|value| self.action == value)
    }

    fn cells(&self) -> Vec<String> {
        vec![
            self.name.clone(),
            if self.enabled { "Yes" } else { "No" }.into(),
            format!("{:?}", self.direction),
            self.fields["profiles"].clone(),
            self.fields["protocol"].clone(),
            self.fields["localport"].clone(),
            self.fields["remoteip"].clone(),
            format!("{:?}", self.action),
            if self.highlighted() { "Yes" } else { "No" }.into(),
        ]
    }
}

struct PendingRule {
    name: String,
    line: usize,
    fields: BTreeMap<String, String>,
}

impl PendingRule {
    fn context(&self, message: &str) -> String {
        format!("line {}, rule {:?}: {message}", self.line, self.name)
    }

    fn finish(self) -> Result<Rule, String> {
        for field in [
            "enabled",
            "direction",
            "profiles",
            "protocol",
            "localport",
            "remoteip",
            "action",
        ] {
            if self.fields.get(field).is_none_or(String::is_empty) {
                return Err(
                    self.context(&format!("missing required field {field:?} or empty value"))
                );
            }
        }
        let enabled =
            parse_enabled(&self.fields["enabled"]).map_err(|message| self.context(&message))?;
        let direction = match self.fields["direction"].to_ascii_lowercase().as_str() {
            "in" => Direction::In,
            "out" => Direction::Out,
            value => return Err(self.context(&format!("unrecognised direction {value:?}"))),
        };
        let action = match self.fields["action"].to_ascii_lowercase().as_str() {
            "allow" => Action::Allow,
            "block" => Action::Block,
            "bypass" => Action::Bypass,
            value => return Err(self.context(&format!("unrecognised action {value:?}"))),
        };
        Ok(Rule {
            name: self.name,
            enabled,
            direction,
            action,
            fields: self.fields,
            line: self.line,
        })
    }
}

fn parse_report(input: &str) -> Result<Vec<Rule>, String> {
    let mut rules = Vec::new();
    let mut pending: Option<PendingRule> = None;
    let mut no_rules = false;
    let mut ended = false;
    for (index, raw) in input.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = raw.trim();
        let number = index + 1;
        if line.is_empty() || line.chars().all(|character| character == '-') {
            continue;
        }
        if ended {
            return Err(format!(
                "line {number}: unexpected text after report ending"
            ));
        }
        if line.eq_ignore_ascii_case("Ok.") {
            ended = true;
            continue;
        }
        if line.eq_ignore_ascii_case("No rules match the specified criteria.") {
            if pending.is_some() || !rules.is_empty() || no_rules {
                return Err(format!("line {number}: unexpected empty-report message"));
            }
            no_rules = true;
            continue;
        }
        let (label, value) = line
            .split_once(':')
            .ok_or_else(|| format!("line {number}: expected a field followed by ':'"))?;
        let key = label.trim().to_ascii_lowercase();
        let value = value.trim();
        if no_rules {
            return Err(format!(
                "line {number}: unexpected field in an empty report"
            ));
        }
        if key == "rule name" && value.is_empty() {
            return Err(format!("line {number}: empty value for {label:?}"));
        }
        if key == "rule name" {
            if let Some(previous) = pending.take() {
                rules.push(previous.finish()?);
            }
            pending = Some(PendingRule {
                name: value.into(),
                line: number,
                fields: BTreeMap::new(),
            });
        } else {
            let rule = pending.as_mut().ok_or_else(|| {
                format!("line {number}: field {label:?} appears before Rule Name")
            })?;
            if rule.fields.contains_key(&key) {
                return Err(format!(
                    "line {number}, rule {:?}: repeated field {label:?}",
                    rule.name
                ));
            }
            rule.fields.insert(key, value.into());
        }
    }
    if let Some(last) = pending {
        rules.push(last.finish()?);
    }
    if rules.is_empty() && !no_rules {
        return Err("no Rule Name records found; expected an English-language netsh report".into());
    }
    rules.sort_by_cached_key(|rule| (rule.name.to_lowercase(), rule.name.clone()));
    Ok(rules)
}

fn decode_report(bytes: &[u8]) -> Result<String, String> {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        let little_endian = bytes[0] == 0xff;
        let data = &bytes[2..];
        if !data.len().is_multiple_of(2) {
            return Err("incomplete UTF-16 code unit".into());
        }
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|pair| {
                if little_endian {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            })
            .collect();
        String::from_utf16(&units).map_err(|error| format!("invalid UTF-16: {error}"))
    } else {
        String::from_utf8(bytes.to_vec()).map_err(|error| {
            format!("invalid UTF-8: {error}; save as UTF-8 or UTF-16 with a byte order mark")
        })
    }
}

fn read_report(path: &Path) -> Result<Vec<Rule>, String> {
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let input = decode_report(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    parse_report(&input).map_err(|error| format!("{}: {error}", path.display()))
}

fn unique_rules(rules: &[Rule]) -> Result<BTreeMap<String, &Rule>, String> {
    let mut unique: BTreeMap<String, &Rule> = BTreeMap::new();
    for rule in rules {
        if let Some(previous) = unique.insert(rule.name.to_lowercase(), rule) {
            return Err(format!(
                "ambiguous duplicate rule name {:?} on lines {} and {} (names are matched case-insensitively)",
                rule.name, previous.line, rule.line
            ));
        }
    }
    Ok(unique)
}

fn differences(before: &Rule, after: &Rule) -> Vec<String> {
    let mut changes = Vec::new();
    if before.name != after.name {
        changes.push(format!("Rule Name: {} -> {}", before.name, after.name));
    }
    let mut keys: Vec<&String> = before.fields.keys().chain(after.fields.keys()).collect();
    keys.sort();
    keys.dedup();
    for key in keys {
        let old = before.fields.get(key);
        let new = after.fields.get(key);
        if old.map(|value| value.to_lowercase()) != new.map(|value| value.to_lowercase()) {
            changes.push(format!(
                "{key}: {} -> {}",
                old.map_or("(absent)", String::as_str),
                new.map_or("(absent)", String::as_str)
            ));
        }
    }
    changes
}

fn escape_cell(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\t' => escaped.push_str("\\t"),
            '\r' => escaped.push_str("\\r"),
            '\n' => escaped.push_str("\\n"),
            value if value.is_control() => {
                write!(escaped, "\\u{{{:x}}}", u32::from(value)).unwrap();
            }
            value => escaped.push(value),
        }
    }
    escaped
}

fn render(headers: &[&str], rows: Vec<Vec<String>>, format: Format) -> String {
    let rows: Vec<Vec<String>> = std::iter::once(headers.iter().map(|s| s.to_string()).collect())
        .chain(rows)
        .map(|row: Vec<String>| row.iter().map(|cell| escape_cell(cell)).collect())
        .collect();
    let mut output = String::new();
    let widths: Vec<usize> = (0..headers.len())
        .map(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    for row in rows {
        for (column, cell) in row.iter().enumerate() {
            if column > 0 {
                output.push_str(match format {
                    Format::Table => "  ",
                    Format::Tsv => "\t",
                });
            }
            output.push_str(cell);
            if matches!(format, Format::Table) && column + 1 < headers.len() {
                output.extend(std::iter::repeat_n(
                    ' ',
                    widths[column] - cell.chars().count(),
                ));
            }
        }
        output.push('\n');
    }
    output
}

fn totals(rules: &[&Rule]) -> String {
    format!(
        "Rules: {}; enabled: {}; highlighted: {}",
        rules.len(),
        rules.iter().filter(|rule| rule.enabled).count(),
        rules.iter().filter(|rule| rule.highlighted()).count()
    )
}

const HIGHLIGHT: &str = "Highlighted means Enabled=Yes, Direction=In, Action=Allow and RemoteIP=Any; these conditions alone do not establish that a rule is unsafe.";

fn execute(cli: Cli) -> Result<String, String> {
    match cli.command {
        Command::Inspect {
            input,
            filters,
            format,
        } => {
            let rules = read_report(&input)?;
            let selected: Vec<&Rule> = rules.iter().filter(|rule| rule.matches(&filters)).collect();
            let mut output = render(
                &[
                    "Rule Name",
                    "Enabled",
                    "Direction",
                    "Profiles",
                    "Protocol",
                    "LocalPort",
                    "RemoteIP",
                    "Action",
                    "Highlighted",
                ],
                selected.iter().map(|rule| rule.cells()).collect(),
                format,
            );
            writeln!(output, "{}", totals(&selected)).unwrap();
            writeln!(output, "{HIGHLIGHT}").unwrap();
            Ok(output)
        }
        Command::Compare {
            before,
            after,
            format,
        } => {
            let old_rules = read_report(&before)?;
            let new_rules = read_report(&after)?;
            let old = unique_rules(&old_rules)
                .map_err(|error| format!("{}: {error}", before.display()))?;
            let new = unique_rules(&new_rules)
                .map_err(|error| format!("{}: {error}", after.display()))?;
            let mut keys: Vec<&String> = old.keys().chain(new.keys()).collect();
            keys.sort();
            keys.dedup();
            let mut rows = Vec::new();
            let (mut added, mut removed, mut changed) = (0, 0, 0);
            for key in keys {
                let (status, rule, details) = match (old.get(key), new.get(key)) {
                    (None, Some(rule)) => {
                        added += 1;
                        ("Added", *rule, String::new())
                    }
                    (Some(rule), None) => {
                        removed += 1;
                        ("Removed", *rule, String::new())
                    }
                    (Some(before), Some(after)) => {
                        let changes = differences(before, after);
                        if changes.is_empty() {
                            continue;
                        }
                        changed += 1;
                        ("Changed", *after, changes.join("; "))
                    }
                    (None, None) => unreachable!(),
                };
                let mut row = vec![status.into()];
                row.extend(rule.cells());
                row.push(details);
                rows.push(row);
            }
            let mut output = render(
                &[
                    "Change",
                    "Rule Name",
                    "Enabled",
                    "Direction",
                    "Profiles",
                    "Protocol",
                    "LocalPort",
                    "RemoteIP",
                    "Action",
                    "Highlighted",
                    "Changed fields",
                ],
                rows,
                format,
            );
            writeln!(
                output,
                "Added: {added}; removed: {removed}; changed: {changed}"
            )
            .unwrap();
            writeln!(
                output,
                "Before: {}",
                totals(&old_rules.iter().collect::<Vec<_>>())
            )
            .unwrap();
            writeln!(
                output,
                "After: {}",
                totals(&new_rules.iter().collect::<Vec<_>>())
            )
            .unwrap();
            writeln!(
                output,
                "Changed rows show later values; removed rows show earlier values."
            )
            .unwrap();
            writeln!(output, "{HIGHLIGHT}").unwrap();
            Ok(output)
        }
    }
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(output) => match io::stdout().lock().write_all(output.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("error: could not write output: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = "Rule Name: Example Web Server\n----------------------------------------------------------------------\nEnabled: Yes\nDirection: In\nProfiles: Private\nLocalIP: Any\nRemoteIP: Any\nProtocol: TCP\nLocalPort: 8080\nRemotePort: Any\nEdge traversal: No\nAction: Allow\n";

    #[test]
    fn parses_boundaries_and_filters_case_insensitively() {
        let input = format!(
            "\u{feff}{}{}Ok.\r\n",
            REPORT.replace('\n', "\r\n"),
            REPORT
                .replace("Example Web Server", "Alpha")
                .replace("Enabled: Yes", "Enabled: No")
        );
        let rules = parse_report(&input).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "Alpha");
        assert!(!rules[0].highlighted());
        assert!(rules[1].highlighted());
        let cli = Cli::try_parse_from([
            "netsh",
            "inspect",
            "report.txt",
            "--name",
            "WEB",
            "--direction",
            "IN",
            "--action",
            "ALLOW",
            "--enabled",
            "yEs",
        ])
        .unwrap();
        let Command::Inspect { filters, .. } = cli.command else {
            panic!()
        };
        assert!(rules[1].matches(&filters));
        assert!(!rules[0].matches(&filters));
    }

    #[test]
    fn rejects_invalid_boolean_missing_and_duplicate_fields() {
        let error = parse_report(&REPORT.replace("Enabled: Yes", "Enabled: Perhaps")).unwrap_err();
        assert!(error.contains("Example Web Server"));
        assert!(error.contains("unrecognised enabled state"));
        assert!(
            parse_report(&REPORT.replace("RemoteIP: Any\n", ""))
                .unwrap_err()
                .contains("missing required field")
        );
        assert!(
            parse_report(&format!("{REPORT}Enabled: No\n"))
                .unwrap_err()
                .contains("repeated field")
        );
        assert!(parse_report("unrelated text").is_err());
        assert!(parse_report("").is_err());
    }

    #[test]
    fn highlights_only_all_four_conditions() {
        for (old, new) in [
            ("Enabled: Yes", "Enabled: No"),
            ("Direction: In", "Direction: Out"),
            ("Action: Allow", "Action: Block"),
            ("RemoteIP: Any", "RemoteIP: 192.0.2.1"),
        ] {
            assert!(!parse_report(&REPORT.replace(old, new)).unwrap()[0].highlighted());
        }
    }

    #[test]
    fn compares_additions_removals_changes_and_extra_fields() {
        let before = parse_report(REPORT).unwrap();
        let after = parse_report(
            &REPORT
                .replace("8080", "443")
                .replace("LocalIP: Any", "LocalIP: 127.0.0.1"),
        )
        .unwrap();
        let changes = differences(&before[0], &after[0]);
        assert_eq!(
            changes,
            ["localip: Any -> 127.0.0.1", "localport: 8080 -> 443"]
        );
        let duplicate = parse_report(&format!(
            "{REPORT}{}",
            REPORT.replace("Example Web Server", "example web server")
        ))
        .unwrap();
        assert!(
            unique_rules(&duplicate)
                .unwrap_err()
                .contains("ambiguous duplicate")
        );
        let old = unique_rules(&before).unwrap();
        let renamed = parse_report(&REPORT.replace("Example Web Server", "Other")).unwrap();
        let new = unique_rules(&renamed).unwrap();
        assert_eq!(old.keys().filter(|key| !new.contains_key(*key)).count(), 1);
        assert_eq!(new.keys().filter(|key| !old.contains_key(*key)).count(), 1);
    }

    #[test]
    fn accepts_explicit_empty_report_and_utf16() {
        assert!(
            parse_report("No rules match the specified criteria.\nOk.\n")
                .unwrap()
                .is_empty()
        );
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend(REPORT.encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_report(&bytes).unwrap(), REPORT);
        bytes.pop();
        assert!(decode_report(&bytes).is_err());
    }

    #[test]
    fn tsv_escapes_cells_and_keeps_stable_columns() {
        assert_eq!(
            render(
                &["Name", "Value"],
                vec![vec!["a\tb".into(), "x\\y".into()]],
                Format::Tsv
            ),
            "Name\tValue\na\\tb\tx\\\\y\n"
        );
    }
}
