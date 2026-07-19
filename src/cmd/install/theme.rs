use std::io::IsTerminal;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Green,
    Purple,
    Blue,
    Black,
    Red,
}

fn color_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }

    if let Ok(value) = std::env::var("ZEX_UI_COLOR") {
        let lowered = value.trim().to_ascii_lowercase();
        return matches!(lowered.as_str(), "1" | "true" | "yes" | "on");
    }

    std::env::var_os("ZEX_FORCE_COLOR").is_some() || std::io::stdout().is_terminal()
}

fn ansi_code(tone: Tone) -> Option<&'static str> {
    match tone {
        Tone::Green => Some("32"),
        Tone::Purple => Some("35"),
        Tone::Blue => Some("36"),
        Tone::Red => Some("31"),
        Tone::Black => None,
    }
}

pub fn paint_with(color_enabled: bool, tone: Tone, text: impl AsRef<str>) -> String {
    let text = text.as_ref();
    if !color_enabled {
        return text.to_string();
    }

    match ansi_code(tone) {
        Some(code) => format!("\x1b[{}m{}\x1b[0m", code, text),
        None => text.to_string(),
    }
}

pub fn paint(tone: Tone, text: impl AsRef<str>) -> String {
    paint_with(color_enabled(), tone, text)
}

pub fn line_with(color_enabled: bool, parts: &[(Tone, &str)]) -> String {
    let mut rendered = String::new();
    for (tone, text) in parts {
        rendered.push_str(&paint_with(color_enabled, *tone, *text));
    }
    rendered
}

pub fn line(parts: &[(Tone, &str)]) -> String {
    line_with(color_enabled(), parts)
}

pub fn kv_line_with(
    color_enabled: bool,
    label_width: usize,
    label: &str,
    value_tone: Tone,
    value: &str,
) -> String {
    let label = format!("{:<width$}", label, width = label_width);
    format!(
        "   {}: {}",
        paint_with(color_enabled, Tone::Green, label),
        paint_with(color_enabled, value_tone, value)
    )
}

pub fn kv_line(label_width: usize, label: &str, value_tone: Tone, value: &str) -> String {
    kv_line_with(color_enabled(), label_width, label, value_tone, value)
}
