//! Deterministic bundling of the web client frontend assets.
use crate::flags;
use anyhow::{anyhow, Context};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use xshell::Shell;

const MODULE_ORDER: &[&str] = &[
    "links",
    "terminal",
    "ime-bypass",
    "soft-keyboard",
    "keyboard",
    "key-handler",
    "mouse",
    "pinch",
    "mobile-pan",
    "touch",
    "input",
    "clip",
    "mobile-ui",
    "native-promote",
    "websockets",
    "app-entry",
];

const BUNDLE_EXPORTS: &[&str] = &[
    "start",
    "shouldUseStandaloneMenu",
    "showStandaloneSessionMenu",
];

const BUNDLE_FILE: &str = "app.js";

const DECLARATION_PREFIXES: &[&str] = &[
    "async function ",
    "function ",
    "const ",
    "let ",
    "var ",
    "class ",
];

pub fn assets(_sh: &Shell, flags: flags::Assets) -> anyhow::Result<()> {
    let msg = if flags.check {
        ">> Checking bundled web client assets"
    } else {
        ">> Bundling web client assets"
    };
    crate::status(msg);
    println!("{}", msg);

    let assets_dir = web_assets_dir();
    let generated = generate(&assets_dir)?;

    if flags.check {
        for (name, contents) in &generated {
            let path = assets_dir.join(name);
            let on_disk = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read '{}'", path.display()))?;
            if &on_disk != contents {
                return Err(anyhow!(
                    "'{}' is out of date, run `cargo xtask assets`",
                    path.display()
                ));
            }
        }
        return Ok(());
    }

    for (name, contents) in &generated {
        let path = assets_dir.join(name);
        std::fs::write(&path, contents)
            .with_context(|| format!("failed to write '{}'", path.display()))?;
    }
    Ok(())
}

fn web_assets_dir() -> PathBuf {
    crate::project_root()
        .join("zellij-web-client-assets")
        .join("assets")
}

fn generate(assets_dir: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let bundle = build_bundle(assets_dir)?;
    Ok(vec![(BUNDLE_FILE.to_string(), bundle)])
}

fn build_bundle(assets_dir: &Path) -> anyhow::Result<String> {
    let mut body = String::new();
    let mut declarations: BTreeMap<String, String> = BTreeMap::new();
    let mut external_imports: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for module in MODULE_ORDER {
        let path = assets_dir.join(format!("{}.js", module));
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read '{}'", path.display()))?;
        let (chunk, externals) = flatten_module(module, &source)?;
        for (specifier, bindings) in externals {
            external_imports
                .entry(specifier)
                .or_default()
                .extend(bindings);
        }
        for name in top_level_declarations(&chunk) {
            if let Some(previous) = declarations.insert(name.clone(), (*module).to_string()) {
                return Err(anyhow!(
                    "duplicate top-level identifier '{}' declared in both '{}.js' and '{}.js'",
                    name,
                    previous,
                    module
                ));
            }
        }
        body.push_str(&chunk);
        if !body.ends_with('\n') {
            body.push('\n');
        }
    }

    for name in BUNDLE_EXPORTS {
        if !declarations.contains_key(*name) {
            return Err(anyhow!(
                "'{}' is exported by the bundle but declared in no bundled module",
                name
            ));
        }
    }

    let mut bundle = String::new();
    for (specifier, bindings) in &external_imports {
        bundle.push_str(&format!(
            "import {{ {} }} from \"{}\";\n",
            bindings.iter().cloned().collect::<Vec<String>>().join(", "),
            specifier
        ));
    }
    if !external_imports.is_empty() {
        bundle.push('\n');
    }
    bundle.push_str(&body);
    bundle.push_str(&format!("export {{ {} }};\n", BUNDLE_EXPORTS.join(", ")));

    Ok(bundle)
}

type ExternalImport = (String, Vec<String>);

fn flatten_module(module: &str, source: &str) -> anyhow::Result<(String, Vec<ExternalImport>)> {
    let mut out = String::new();
    let mut externals: Vec<ExternalImport> = Vec::new();
    let mut lines = source.lines().enumerate().peekable();

    while let Some((index, line)) = lines.next() {
        let location = || format!("{}.js:{}", module, index + 1);

        if line.contains("import(") {
            return Err(anyhow!("dynamic import is not supported at {}", location()));
        }

        if let Some(rest) = line.strip_prefix("import ") {
            if is_terminated_import(rest) {
                if validate_module_specifier(rest, &location())? {
                    externals.push(parse_external_import(line, &location())?);
                }
                continue;
            }
            let mut statement = vec![line.to_string()];
            let mut terminated = false;
            for (_, continuation) in lines.by_ref() {
                let trimmed = continuation.trim_start();
                statement.push(continuation.to_string());
                if trimmed.starts_with("} from ") && trimmed.ends_with(';') {
                    if validate_module_specifier(trimmed, &location())? {
                        externals.push(parse_external_import(&statement.join(" "), &location())?);
                    }
                    terminated = true;
                    break;
                }
                if !is_import_binding_line(trimmed) {
                    return Err(anyhow!("unrecognised import syntax at {}", location()));
                }
            }
            if !terminated {
                return Err(anyhow!("unterminated import statement at {}", location()));
            }
            continue;
        }

        if line.starts_with("export ") || line.starts_with("export{") {
            if line.starts_with("export {") {
                if line.contains(" from ") {
                    validate_module_specifier(line, &location())?;
                    continue;
                }
                return Err(anyhow!("unrecognised export syntax at {}", location()));
            }
            if line.starts_with("export default") || line.starts_with("export *") {
                return Err(anyhow!("unsupported export form at {}", location()));
            }
            let stripped = &line["export ".len()..];
            if !DECLARATION_PREFIXES
                .iter()
                .any(|prefix| stripped.starts_with(prefix))
            {
                return Err(anyhow!("unrecognised export syntax at {}", location()));
            }
            out.push_str(stripped);
            out.push('\n');
            continue;
        }

        out.push_str(line);
        out.push('\n');
    }

    Ok((out, externals))
}

fn parse_external_import(statement: &str, location: &str) -> anyhow::Result<ExternalImport> {
    let (bindings, specifier) = statement
        .rsplit_once(" from ")
        .ok_or_else(|| anyhow!("missing module specifier at {}", location))?;
    let specifier = specifier
        .trim()
        .trim_end_matches(';')
        .trim_matches(|c| c == '"' || c == '\'')
        .to_string();
    let bindings = bindings
        .trim()
        .trim_start_matches("import")
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .split(',')
        .map(|binding| binding.trim().to_string())
        .filter(|binding| !binding.is_empty())
        .collect::<Vec<String>>();
    if bindings.is_empty() {
        return Err(anyhow!("no named bindings in import at {}", location));
    }
    Ok((specifier, bindings))
}

fn is_terminated_import(rest: &str) -> bool {
    rest.ends_with(';') && rest.contains(" from ")
}

fn is_import_binding_line(trimmed: &str) -> bool {
    if trimmed.is_empty() || trimmed == "{" {
        return true;
    }
    trimmed
        .trim_end_matches(',')
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '$' || c == ' ')
}

fn validate_module_specifier(line: &str, location: &str) -> anyhow::Result<bool> {
    let specifier = line
        .rsplit_once(" from ")
        .map(|(_, specifier)| specifier)
        .ok_or_else(|| anyhow!("missing module specifier at {}", location))?
        .trim()
        .trim_end_matches(';')
        .trim_matches(|c| c == '"' || c == '\'');

    if let Some(name) = specifier
        .strip_prefix("/assets/")
        .and_then(|name| name.strip_suffix(".js"))
    {
        if MODULE_ORDER.contains(&name) {
            return Err(anyhow!(
                "bundled module '{}' must be imported as './{}.js', not '{}', at {}",
                name,
                name,
                specifier,
                location
            ));
        }
        if !zellij_web_client_assets::manifest::HANDSHAKE_CORE_ASSET_NAMES
            .contains(&format!("{}.js", name).as_str())
        {
            return Err(anyhow!(
                "'{}' referenced at {} is neither a bundled module nor a handshake-core asset",
                specifier,
                location
            ));
        }
        return Ok(true);
    }

    let name = specifier
        .strip_prefix("./")
        .and_then(|name| name.strip_suffix(".js"))
        .ok_or_else(|| {
            anyhow!(
                "only './<module>.js' and '/assets/<core>.js' specifiers are supported, found '{}' at {}",
                specifier,
                location
            )
        })?;

    if !MODULE_ORDER.contains(&name) {
        return Err(anyhow!(
            "module '{}' referenced at {} is not part of the bundle",
            name,
            location
        ));
    }
    Ok(false)
}

fn top_level_declarations(chunk: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in chunk.lines() {
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        for prefix in DECLARATION_PREFIXES {
            let Some(rest) = line.strip_prefix(prefix) else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            if !name.is_empty() {
                names.push(name);
            }
            break;
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_imports_are_dropped() {
        let source = "import { a } from \"./links.js\";\nexport function b() {}\n";
        let (flattened, externals) = flatten_module("terminal", source).expect("flatten");
        assert_eq!(flattened, "function b() {}\n");
        assert!(externals.is_empty());
    }

    #[test]
    fn handshake_core_imports_are_preserved() {
        let source = "import { getBaseUrl } from \"/assets/utils.js\";\nconst c = 1;\n";
        let (flattened, externals) = flatten_module("terminal", source).expect("flatten");
        assert_eq!(flattened, "const c = 1;\n");
        assert_eq!(
            externals,
            vec![(
                "/assets/utils.js".to_string(),
                vec!["getBaseUrl".to_string()]
            )]
        );
    }

    #[test]
    fn multiline_imports_are_dropped() {
        let source = "import {\n    a,\n    b,\n} from \"./links.js\";\nconst c = 1;\n";
        let (flattened, _) = flatten_module("terminal", source).expect("flatten");
        assert_eq!(flattened, "const c = 1;\n");
    }

    #[test]
    fn re_exports_are_dropped() {
        let source = "export { setSoftKeyboard } from \"./soft-keyboard.js\";\n";
        let (flattened, _) = flatten_module("input", source).expect("flatten");
        assert_eq!(flattened, "");
    }

    #[test]
    fn unsupported_export_forms_are_rejected() {
        assert!(flatten_module("terminal", "export default function a() {}\n").is_err());
        assert!(flatten_module("terminal", "export * from \"./links.js\";\n").is_err());
        assert!(flatten_module("terminal", "export unexpected;\n").is_err());
    }

    #[test]
    fn unknown_module_specifiers_are_rejected() {
        assert!(flatten_module("terminal", "import { a } from \"nowhere\";\n").is_err());
        assert!(flatten_module("terminal", "import { a } from \"./nowhere.js\";\n").is_err());
        assert!(flatten_module("terminal", "import { a } from \"/assets/nowhere.js\";\n").is_err());
    }

    #[test]
    fn bundled_modules_may_not_be_imported_through_the_assets_path() {
        assert!(flatten_module("input", "import { a } from \"/assets/terminal.js\";\n").is_err());
    }

    #[test]
    fn dynamic_imports_are_rejected() {
        assert!(flatten_module("terminal", "const m = await import(\"./links.js\");\n").is_err());
    }

    #[test]
    fn duplicate_top_level_identifiers_are_detected() {
        let dir = std::env::temp_dir().join("zellij-xtask-assets-duplicate-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        for module in MODULE_ORDER {
            let contents = if *module == "links" || *module == "terminal" {
                "function collide() {}\n"
            } else {
                ""
            };
            std::fs::write(dir.join(format!("{}.js", module)), contents).expect("write module");
        }

        let error = build_bundle(&dir).expect_err("expected duplicate detection to fail");
        assert!(
            error.to_string().contains("duplicate top-level identifier"),
            "unexpected error: {}",
            error
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn top_level_declarations_ignores_nested_scopes() {
        let chunk = "function outer() {\n    const inner = 1;\n}\nconst top = 2;\n";
        assert_eq!(top_level_declarations(chunk), vec!["outer", "top"]);
    }

}
