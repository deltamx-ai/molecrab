use colored::Colorize;
use std::process::Command;

#[derive(Clone, Copy)]
struct ToolCheck {
    name: &'static str,
    command: &'static str,
    args: &'static [&'static str],
    install_hint: &'static str,
    required: bool,
}

struct ToolResult {
    name: &'static str,
    required: bool,
    installed: bool,
    version_output: Option<String>,
    error: Option<String>,
    install_hint: &'static str,
    command: &'static str,
}

pub fn run() {
    let tools = [
        ToolCheck {
            name: "git",
            command: "git",
            args: &["--version"],
            install_hint: "Install Git, then make sure `git` is in your PATH.",
            required: true,
        },
        ToolCheck {
            name: "rustc",
            command: "rustc",
            args: &["--version"],
            install_hint: "Install Rust (rustup), then make sure `rustc` is in your PATH.",
            required: true,
        },
        ToolCheck {
            name: "cargo",
            command: "cargo",
            args: &["--version"],
            install_hint: "Install Rust (rustup), then make sure `cargo` is in your PATH.",
            required: true,
        },
        ToolCheck {
            name: "node",
            command: "node",
            args: &["--version"],
            install_hint: "Install Node.js, then make sure `node` is in your PATH.",
            required: true,
        },
        ToolCheck {
            name: "python3",
            command: "python3",
            args: &["--version"],
            install_hint: "Install Python 3, then make sure `python3` is in your PATH.",
            required: true,
        },
        ToolCheck {
            name: "npm",
            command: "npm",
            args: &["--version"],
            install_hint: "Install npm, then make sure `npm` is in your PATH.",
            required: true,
        },
        ToolCheck {
            name: "pnpm",
            command: "pnpm",
            args: &["--version"],
            install_hint: "Install pnpm if you prefer it, then make sure `pnpm` is in your PATH.",
            required: false,
        },
        ToolCheck {
            name: "yarn",
            command: "yarn",
            args: &["--version"],
            install_hint: "Install Yarn if you prefer it, then make sure `yarn` is in your PATH.",
            required: false,
        },
    ];

    let results: Vec<ToolResult> = tools.iter().map(check_tool).collect();
    let required_total = results.iter().filter(|r| r.required).count();
    let required_ok = results.iter().filter(|r| r.required && r.installed).count();
    let healthy = required_ok;
    let unhealthy_required = required_total.saturating_sub(required_ok);
    let all_required_ok = unhealthy_required == 0;

    print_banner();

    if all_required_ok {
        print_health_report(&results);
    } else {
        print_unhealthy_report(&results, healthy, unhealthy_required);
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

fn warning_label() -> String {
    "WARN".bold().black().on_yellow().to_string()
}

fn section_title(text: &str) {
    println!("{}", text.bold().white());
    println!("{}", "-".repeat(text.len()).dimmed());
}

fn print_health_report(results: &[ToolResult]) {
    println!(
        "{} {}",
        status_label(true),
        "Environment looks healthy".green().bold()
    );
    println!("All required tools are installed and responding normally.");
    println!();

    section_title("Checks");
    for result in results {
        render_result(result);
    }

    println!();
    println!(
        "{}",
        "Everything looks good. You can use this environment normally.".green()
    );
}

fn print_unhealthy_report(results: &[ToolResult], healthy: usize, unhealthy_required: usize) {
    println!(
        "{} {}",
        status_label(false),
        "Environment needs attention".red().bold()
    );
    println!("Some required tools are missing or not usable.");
    println!();

    section_title("Checks");
    for result in results {
        render_result(result);
    }

    println!();
    section_title("Summary");
    println!("Healthy required tools: {}", healthy.to_string().green());
    println!(
        "Missing required tools: {}",
        unhealthy_required.to_string().red()
    );
    println!();
    println!(
        "{}",
        "Tip: fix the failed required tools above and run `molecrab doctor` again.".cyan()
    );
}

fn render_result(result: &ToolResult) {
    let version = result
        .version_output
        .as_deref()
        .unwrap_or("version unavailable")
        .trim();

    match (result.required, result.installed) {
        (true, true) => {
            println!(
                "{} {:<10} {}",
                status_label(true),
                result.name.bold(),
                version.dimmed()
            );
        }
        (true, false) => {
            println!(
                "{} {:<10} {}",
                status_label(false),
                result.name.bold(),
                "not ready (required)".red()
            );
            if let Some(err) = &result.error {
                println!("   {} {}", "reason:".yellow().bold(), err);
            }
            println!("   {} {}", "fix:".yellow().bold(), result.install_hint);
            println!(
                "   {} {}",
                "verify:".yellow().bold(),
                format!("{} --version", result.command).dimmed()
            );
        }
        (false, true) => {
            println!(
                "{} {:<10} {}",
                status_label(true),
                result.name.bold(),
                format!("{} (optional)", version).dimmed()
            );
        }
        (false, false) => {
            println!(
                "{} {:<10} {}",
                warning_label(),
                result.name.bold(),
                "not installed (optional)".yellow()
            );
            println!(
                "   {} optional tool not found in PATH.",
                "reason:".yellow().bold()
            );
            println!("   {} {}", "fix:".yellow().bold(), result.install_hint);
            println!(
                "   {} {}",
                "verify:".yellow().bold(),
                format!("{} --version", result.command).dimmed()
            );
        }
    }
}

fn check_tool(tool: &ToolCheck) -> ToolResult {
    match Command::new(tool.command).args(tool.args).output() {
        Ok(output) => ToolResult {
            name: tool.name,
            required: tool.required,
            installed: output.status.success(),
            version_output: collect_version_output(&output.stdout, &output.stderr),
            error: if output.status.success() {
                None
            } else {
                Some(format!(
                    "command exited with status {} when running `{}`",
                    output.status, tool.command
                ))
            },
            install_hint: tool.install_hint,
            command: tool.command,
        },
        Err(err) => ToolResult {
            name: tool.name,
            required: tool.required,
            installed: false,
            version_output: None,
            error: Some(format!("failed to execute `{}`: {}", tool.command, err)),
            install_hint: tool.install_hint,
            command: tool.command,
        },
    }
}

fn collect_version_output(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let stdout = String::from_utf8_lossy(stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(stderr).trim().to_owned();

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => None,
        (false, true) => Some(stdout),
        (true, false) => Some(stderr),
        (false, false) => Some(format!("{} {}", stdout, stderr)),
    }
}
