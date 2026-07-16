use std::{env, fs, io::Read, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use toml_edit::{DocumentMut, value};
use xtask_kit::{fs::write_string, process::ExitCode};

use crate::CheckToolUpdatesArgs;

const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

struct Tool {
    name: &'static str,
    repo: Option<&'static str>,
    arm64_url: &'static str,
    x86_64_url: &'static str,
}

const TOOLS: &[Tool] = &[
    Tool {
        name: "docker",
        repo: Some("moby/moby"),
        arm64_url: "https://download.docker.com/mac/static/stable/aarch64/docker-{version}.tgz",
        x86_64_url: "https://download.docker.com/mac/static/stable/x86_64/docker-{version}.tgz",
    },
    Tool {
        name: "docker-buildx",
        repo: Some("docker/buildx"),
        arm64_url: "https://github.com/docker/buildx/releases/download/v{version}/buildx-v{version}.darwin-arm64",
        x86_64_url: "https://github.com/docker/buildx/releases/download/v{version}/buildx-v{version}.darwin-amd64",
    },
    Tool {
        name: "docker-compose",
        repo: Some("docker/compose"),
        arm64_url: "https://github.com/docker/compose/releases/download/v{version}/docker-compose-darwin-aarch64",
        x86_64_url: "https://github.com/docker/compose/releases/download/v{version}/docker-compose-darwin-x86_64",
    },
    Tool {
        name: "docker-credential-osxkeychain",
        repo: Some("docker/docker-credential-helpers"),
        arm64_url: "https://github.com/docker/docker-credential-helpers/releases/download/v{version}/docker-credential-osxkeychain-v{version}.darwin-arm64",
        x86_64_url: "https://github.com/docker/docker-credential-helpers/releases/download/v{version}/docker-credential-osxkeychain-v{version}.darwin-amd64",
    },
    Tool {
        name: "kubectl",
        repo: None,
        arm64_url: "https://dl.k8s.io/release/v{version}/bin/darwin/arm64/kubectl",
        x86_64_url: "https://dl.k8s.io/release/v{version}/bin/darwin/amd64/kubectl",
    },
];

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
}

pub fn run(args: CheckToolUpdatesArgs) -> Result<()> {
    let client = Client::builder().timeout(HTTP_TIMEOUT).build()?;
    let original = fs::read_to_string(&args.lockfile)
        .with_context(|| format!("reading {}", args.lockfile.display()))?;
    let mut doc = original
        .parse::<DocumentMut>()
        .with_context(|| format!("parsing {}", args.lockfile.display()))?;
    let mut updates = Vec::new();

    for tool in TOOLS {
        let Some(current) = current_version(&doc, tool.name) else {
            eprintln!(
                "  {}: not found in {}, skipping",
                tool.name,
                args.lockfile.display()
            );
            continue;
        };
        let latest = latest_version(&client, tool)?;
        if current == latest {
            eprintln!("  {}: {current} (up to date)", tool.name);
            continue;
        }

        eprintln!(
            "  {}: {current} -> {latest}  (downloading checksums...)",
            tool.name
        );
        let arm_sha = sha256_url(&client, &tool.arm64_url.replace("{version}", &latest))?;
        let x86_sha = sha256_url(&client, &tool.x86_64_url.replace("{version}", &latest))?;
        update_tool(&mut doc, tool.name, &latest, &arm_sha, &x86_sha)?;
        updates.push(format!("- `{}`: {current} -> {latest}", tool.name));
    }

    if updates.is_empty() {
        eprintln!("All tools are up to date.");
        return Err(ExitCode::new(2).into());
    }

    write_string(&args.lockfile, doc.to_string())?;
    println!("{}", updates.join("\n"));
    Ok(())
}

fn latest_version(client: &Client, tool: &Tool) -> Result<String> {
    if let Some(repo) = tool.repo {
        let mut request = client
            .get(format!(
                "https://api.github.com/repos/{repo}/releases/latest"
            ))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "arcbox-xtask");
        if let Ok(token) = env::var("GH_TOKEN") {
            request = request.bearer_auth(token);
        }
        let release = request
            .send()
            .with_context(|| format!("fetching latest release for {repo}"))?
            .error_for_status()
            .with_context(|| format!("GitHub latest release request failed for {repo}"))?
            .json::<GithubRelease>()
            .with_context(|| format!("decoding latest release for {repo}"))?;
        Ok(version_from_tag(&release.tag_name))
    } else {
        Ok(client
            .get("https://dl.k8s.io/release/stable.txt")
            .send()
            .context("fetching latest kubectl version")?
            .error_for_status()
            .context("kubectl stable.txt request failed")?
            .text()
            .context("reading kubectl stable.txt")?
            .trim()
            .trim_start_matches('v')
            .to_owned())
    }
}

/// Extracts the bare version from a release tag by dropping everything up to
/// the first digit: `v0.35.0` → `0.35.0`, and moby's post-split scheme
/// `docker-v29.6.1` → `29.6.1`.
fn version_from_tag(tag: &str) -> String {
    match tag.find(|c: char| c.is_ascii_digit()) {
        Some(idx) => tag[idx..].to_owned(),
        None => tag.to_owned(),
    }
}

fn sha256_url(client: &Client, url: &str) -> Result<String> {
    let mut response = client
        .get(url)
        .send()
        .with_context(|| format!("downloading {url}"))?
        .error_for_status()
        .with_context(|| format!("download failed for {url}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = response
            .read(&mut buffer)
            .with_context(|| format!("reading {url}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn current_version(doc: &DocumentMut, name: &str) -> Option<String> {
    doc["tools"]
        .as_array_of_tables()?
        .iter()
        .find(|tool| tool["name"].as_str() == Some(name))?
        .get("version")?
        .as_str()
        .map(str::to_owned)
}

fn update_tool(
    doc: &mut DocumentMut,
    name: &str,
    version: &str,
    arm_sha: &str,
    x86_sha: &str,
) -> Result<()> {
    let tools = doc["tools"]
        .as_array_of_tables_mut()
        .context("assets.lock is missing [[tools]] entries")?;
    let Some(tool) = tools
        .iter_mut()
        .find(|tool| tool["name"].as_str() == Some(name))
    else {
        bail!("tool not found in assets.lock: {name}");
    };
    tool["version"] = value(version);
    tool["arch"]["arm64"]["sha256"] = value(arm_sha);
    tool["arch"]["x86_64"]["sha256"] = value(x86_sha);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::version_from_tag;

    #[test]
    fn version_from_tag_handles_all_upstream_schemes() {
        assert_eq!(version_from_tag("v0.35.0"), "0.35.0");
        assert_eq!(version_from_tag("docker-v29.6.1"), "29.6.1");
        assert_eq!(version_from_tag("29.3.1"), "29.3.1");
    }
}
