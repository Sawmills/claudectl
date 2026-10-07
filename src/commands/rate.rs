use anyhow::Result;
use claudectl::config;
use claudectl::rate::{self, AccountRate};
use comfy_table::{
    Attribute, Cell, Color, Table, modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL,
};

pub fn run(minutes: u32, json: bool) -> Result<()> {
    let paths = config::default_paths()?;
    let now = chrono::Utc::now();
    let since = now - chrono::Duration::minutes(i64::from(minutes));
    let accounts = rate::collect(&paths, since, now)?;
    if json {
        let report = serde_json::json!({
            "version": 1,
            "window_minutes": minutes,
            "accounts": accounts,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    if accounts.is_empty() {
        println!("no claudectl claude lane activity in the last {minutes} min");
        return Ok(());
    }
    println!("window {minutes} min, claudectl claude lanes only");
    println!("{}", table(&accounts));
    Ok(())
}

fn table(accounts: &[AccountRate]) -> Table {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.style_text_only();
    table.apply_modifier(UTF8_ROUND_CORNERS);
    table.set_header(["Account", "Lanes", "OK", "429", "429 rate"].map(|label| {
        Cell::new(label)
            .fg(Color::Cyan)
            .add_attribute(Attribute::Bold)
    }));
    for account in accounts {
        let percent = account.rate_limited_percent();
        let rate = Cell::new(format!("{percent:.1}%"));
        table.add_row([
            Cell::new(account.alias.as_deref().unwrap_or("(outside a lane run)")),
            Cell::new(account.lanes.iter().cloned().collect::<Vec<_>>().join(", ")),
            Cell::new(account.ok),
            Cell::new(account.rate_limited),
            if account.rate_limited > 0 {
                rate.fg(Color::Red)
            } else {
                rate
            },
        ]);
    }
    table
}
