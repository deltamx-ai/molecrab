use colored::Colorize;
use std::fmt::Write as _;
use std::process::Command;

struct ToolCheck {
    name: &'static str,
    command: &'static str,
    args: &'static [&'static str],
    install_hint: &'static str,
}

struct CheckResult {
    name: &'static str,
    installed: bool,
    exit_ok: bool,
    version_output: Option<String>,
    error: Option<String>,
}

pub fn run() {
    let tools = [
        ToolCheck {
            name: "git",
            command: "git",
            args: &["--version"],
            install_hint: "Install Git, then make sure `git` is in your PATH.",
        },
        ToolCheck {
            name: "node",
            command: "node",
            args: &["--version"],
            install_hint: "Install Node.js, then make sure `node` is in your PATH.",
        },
        ToolCheck {
            name: "npm",
            command: "npm",
            args: &["--version"],
            install_hint: "Install npm together with Node.js, then make sure `npm` is in your PATH.",
        },
    ];

    let results: Vec<CheckResult> = tools.iter().map(check_tool).collect();
    let all_ok = results.iter().all(|r| r.installed && r.exit_ok);

    print_banner();

    if all_ok {
        print_health_report(&results);
    } else {
        print_unhealthy_report(&results, &tools);
    }
}

fn print_banner() {
    println!("{}", "molecrab doctor".bold().cyan());
    println!("{}", "================".cyan());
    println!();
}

fn status_label(ok: bool) -> String {
    if ok {
        " OK ".bold().black().on_green().to_string()
    } else {
        "FAIL".bold().white().on_red().to_string()
    }
}

fn section_title(text: &str) {
    println!("{}", text.bold().white());
    println!("{}", "-".repeat(text.len()).dimmed());
}

fn print_health_report(results: &[CheckResult]) {
    println!(
        "{} {}",
        status_label(true),
        "Environment looks healthy".green().bold()
    );
    println!("All required tools are installed and responding normally.");
    println!();

    section_title("Checks");
    for result in results {
        let version = result
            .version_output
            .as_deref()
            .unwrap_or("version unavailable")
            .trim();
        println!(
            "{} {:<8} {}",
            status_label(true),
            result.name.bold(),
            version.dimmed()
        );
    }
    println!();
    println!(
        "{}",
        "Everything looks good. You can use this environment normally.".green()
    );
}

fn print_unhealthy_report(results: &[CheckResult], tools: &[ToolCheck]) {
    println!(
        "{} {}",
        status_label(false),
        "Environment needs attention".red().bold()
    );
    println!("Some required tools are missing or not usable.");
    println!();

    section_title("Checks");

    let mut unhealthy_count = 0;
    for result in results {
        if result.installed && result.exit_ok {
            let version = result
                .version_output
                .as_deref()
                .unwrap_or("version unavailable")
                .trim();
            println!(
                "{} {:<8} {}",
                status_label(true),
                result.name.bold(),
                version.dimmed()
            );
        } else {
            unhealthy_count += 1;
            println!(
                "{} {:<8} {}",
                status_label(false),
                result.name.bold(),
                "not ready".red()
            );
            if let Some(err) = &result.error {
                println!("   {} {}", "reason:".yellow().bold(), err);
            }
            if let Some(tool) = tools.iter().find(|tool| tool.name == result.name) {
                println!("   {} {}", "fix:".yellow().bold(), tool.install_hint);
                println!(
                    "   {} {}",
                    "verify:".yellow().bold(),
                    format!("{} --version", tool.command).dimmed()
                );
            }
        }
    }

    println!();
    section_title("Summary");
    println!(
        "Healthy:   {}",
        results
            .iter()
            .filter(|r| r.installed && r.exit_ok)
            .count()
            .to_string()
            .green()
    );
    println!("Unhealthy: {}", unhealthy_count.to_string().red());
    println!();
    println!(
        "{}",
        "Tip: fix the failed tools above and run `molecrab doctor` again.".cyan()
    );
}

fn check_tool(tool: &ToolCheck) -> CheckResult {
    match Command::new(tool.command).args(tool.args).output() {
        Ok(output) => {
            let mut version_output = String::new();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stdout.trim().is_empty() {
                let _ = write!(version_output, "{}", stdout.trim());
            }
            if !stderr.trim().is_empty() {
                if !version_output.is_empty() {
                    version_output.push(' ');
                }
                let _ = write!(version_output, "{}", stderr.trim());
            }

            CheckResult {
                name: tool.name,
                installed: true,
                exit_ok: output.status.success(),
                version_output: if version_output.is_empty() {
                    None
                } else {
                    Some(version_output)
                },
                error: if output.status.success() {
                    None
                } else {
                    Some(format!(
                        "command exited with status {} when running `{}`",
                        output.status, tool.command
                    ))
                },
            }
        }
        Err(err) => CheckResult {
            name: tool.name,
            installed: false,
            exit_ok: false,
            version_output: None,
            error: Some(format!("failed to execute `{}`: {}", tool.command, err)),
        },
    }
}
