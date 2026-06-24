pub(super) const KUBERNETES_HOST_ENDPOINT: &str = "https://127.0.0.1:16443";

pub(super) fn rewrite_kubeconfig_server(kubeconfig: &str) -> String {
    kubeconfig
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            let indent = " ".repeat(line.len() - trimmed.len());

            match trimmed {
                _ if trimmed.starts_with("server:") => {
                    format!("{indent}server: {KUBERNETES_HOST_ENDPOINT}")
                }
                "name: default" => format!("{indent}name: arcbox"),
                "- name: default" => format!("{indent}- name: arcbox"),
                "cluster: default" => format!("{indent}cluster: arcbox"),
                "user: default" => format!("{indent}user: arcbox"),
                "current-context: default" => format!("{indent}current-context: arcbox"),
                _ => line.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
