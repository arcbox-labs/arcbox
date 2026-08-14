pub(super) fn host_endpoint(port: u16) -> String {
    format!("https://127.0.0.1:{port}")
}

pub(super) fn rewrite_kubeconfig(kubeconfig: &str, endpoint: &str, context_name: &str) -> String {
    kubeconfig
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            let indent = " ".repeat(line.len() - trimmed.len());

            match trimmed {
                _ if trimmed.starts_with("server:") => {
                    format!("{indent}server: {endpoint}")
                }
                "name: default" => format!("{indent}name: {context_name}"),
                "- name: default" => format!("{indent}- name: {context_name}"),
                "cluster: default" => format!("{indent}cluster: {context_name}"),
                "user: default" => format!("{indent}user: {context_name}"),
                "current-context: default" => {
                    format!("{indent}current-context: {context_name}")
                }
                _ => line.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
