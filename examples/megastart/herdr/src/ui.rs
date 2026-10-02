//! Terminal views observe the same host as the browser. No agent is launched here.
use crate::client::{self, Action, Cursor, Operator, Selection, Snapshot};
use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use serde_json::Value;
use std::{io, path::Path, sync::mpsc, time::Duration};

enum Update {
    State(Box<Snapshot>),
    Error(String),
    Accepted,
}
enum Command {
    Action(Action),
    Browser,
}
struct Screen;
impl Drop for Screen {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

pub fn run(path: &Path, initial: &str) -> Result<()> {
    use std::io::IsTerminal;
    anyhow::ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "The mission board needs a terminal; use chio-herdr status for structured output"
    );
    let path = path.to_owned();
    let (updates, incoming) = mpsc::channel();
    let (commands, outgoing) = mpsc::channel();
    std::thread::spawn(move || {
        let mut cursor = Cursor::default();
        loop {
            let command = match outgoing.try_recv() {
                Ok(command) => Some(command),
                Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => None,
            };
            let result = (|| -> Result<()> {
                let operator = Operator::connect(&path)?;
                match command {
                    Some(Command::Action(action)) => {
                        operator.action(&action)?;
                        let _ = updates.send(Update::Accepted);
                    }
                    Some(Command::Browser) => crate::browser(&operator)?,
                    None => (),
                }
                let state = operator.snapshot()?;
                if let Err(error) = crate::notify(&path, &state) {
                    // Notification transport is advisory; failure never changes
                    // mission state or prevents operator inspection.
                    let _ = std::fs::write(
                        path.with_extension("notification-error.txt"),
                        format!("{error:#}"),
                    );
                }
                // A gap invalidates the cursor, never invents events or repeats work.
                if operator.events(&mut cursor).is_err() {
                    cursor.sequence = 0;
                    operator.events(&mut cursor)?;
                }
                updates
                    .send(Update::State(Box::new(state)))
                    .context("View closed")?;
                Ok(())
            })();
            if let Err(error) = result {
                if updates.send(Update::Error(format!("{error:#}"))).is_err() {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(800));
        }
    });
    enable_raw_mode()?;
    let _screen = Screen;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut state: Option<Box<Snapshot>> = None;
    let mut connected = false;
    let mut message = "Connecting to your Chio mission…".to_string();
    let mut view = if initial == "resume" {
        "mission"
    } else {
        initial
    }
    .to_string();
    let mut selected = 0usize;
    let mut scroll = 0u16;
    let mut pending: Option<(String, Action)> = None;
    let mut in_flight = false;
    let mut selection = Selection {
        research: "hermes".into(),
        implementation: "hermes".into(),
        review: "hermes".into(),
    };
    let color =
        std::env::var_os("NO_COLOR").is_none() && std::env::var("TERM").as_deref() != Ok("dumb");
    loop {
        while let Ok(update) = incoming.try_recv() {
            match update {
                Update::State(snapshot) => {
                    if state.is_none()
                        && initial == "resume"
                        && snapshot.state["phase"] != "setup"
                        && !snapshot.busy
                    {
                        pending = Some((
                            "Reconcile retained work and resume the existing mission?".into(),
                            Action::Resume,
                        ));
                    }
                    if !connected && state.is_some() {
                        message = "Connection restored. Inspect retained outcomes before retrying an unconfirmed action.".into();
                    }
                    if state.is_none() {
                        message = if snapshot.state["phase"] == "setup" {
                            "Choose your agents, prepare their connections, then initialize a mission."
                        } else {
                            "Inspect retained work. Closing this view leaves the mission running."
                        }
                        .into();
                    }
                    state = Some(snapshot);
                    connected = true;
                }
                Update::Error(error) => {
                    connected = false;
                    in_flight = false;
                    pending = None;
                    message = format!(
                        "Disconnected or action unconfirmed · {}",
                        client::text(&error)
                    );
                }
                Update::Accepted => {
                    in_flight = false;
                    message = "Host accepted the request. Follow retained outcomes for completion."
                        .into();
                }
            }
        }
        terminal.draw(|frame| {
            let area = frame.area();
            let accent = if color { Color::Rgb(183, 139, 239) } else { Color::Reset };
            let rows = Layout::vertical([Constraint::Length(3), Constraint::Min(4), Constraint::Length(4)]).split(area);
            let title = format!(" CHIO  ·  Your agents. A system built on Chio.\n {}  /  {}", if connected { "Connected" } else { "Disconnected · last retained state" }, view);
            frame.render_widget(Paragraph::new(title).style(Style::default().fg(accent)), rows[0]);
            if let Some(snapshot) = &state {
                if snapshot.state["phase"] == "setup" {
                    setup(frame, rows[1], snapshot, &selection, accent);
                } else if view == "mission" {
                    mission(frame, rows[1], snapshot, accent);
                } else {
                    let content = detail(snapshot, &view, selected);
                    frame.render_widget(Paragraph::new(client::text(&content)).wrap(Wrap { trim: false }).scroll((scroll, 0))
                        .block(Block::default().borders(Borders::TOP).title(format!(" {} · ↑↓ select · PgUp/PgDn scroll ", view))), rows[1]);
                }
            } else { frame.render_widget(Paragraph::new("Waiting for authenticated mission state. No work is submitted by opening this view."), rows[1]); }
            let footer = if let Some((prompt, _)) = &pending { format!("{}\nEnter confirms · Escape cancels", prompt) }
            else { format!("{}\n1 mission · 2 decisions · 3 candidate · 4 events · r run/resume · a approve · x exercise · b browser · q close view", message) };
            frame.render_widget(Paragraph::new(client::text(&footer)).wrap(Wrap { trim: true }).block(Block::default().borders(Borders::TOP)), rows[2]);
        })?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.code == KeyCode::Char('q') {
            break;
        }
        if key.code == KeyCode::Esc {
            pending = None;
            continue;
        }
        if key.code == KeyCode::Enter {
            if connected && !in_flight {
                if let Some((_, action)) = pending.take() {
                    commands.send(Command::Action(action))?;
                    in_flight = true;
                    message = "Request submitted; waiting for host confirmation…".into();
                }
            }
            continue;
        }
        // Any other input invalidates the pending confirmation. In particular,
        // editing a role must never confirm an older, invisible selection.
        pending = None;
        let ready = connected && !in_flight && state.as_ref().is_some_and(|s| !s.busy);
        if state.as_ref().is_some_and(|s| s.state["phase"] == "setup") {
            match key.code {
                KeyCode::Char('1') => cycle(&mut selection.research),
                KeyCode::Char('2') => cycle(&mut selection.implementation),
                KeyCode::Char('3') => cycle(&mut selection.review),
                KeyCode::Char('h') => {
                    selection = Selection {
                        research: "hermes".into(),
                        implementation: "hermes".into(),
                        review: "hermes".into(),
                    }
                }
                KeyCode::Char('m') => {
                    selection = Selection {
                        research: "hermes".into(),
                        implementation: "codex".into(),
                        review: "pi".into(),
                    }
                }
                KeyCode::Char('i') if ready => {
                    pending = Some((
                        "Create a mission with these agent roles and one shared allowance?".into(),
                        Action::Initialize {
                            native: selection.clone(),
                        },
                    ))
                }
                KeyCode::Char('c') if ready => {
                    let snapshot = state.as_ref().context("Missing setup state")?;
                    let chosen = [
                        &selection.research,
                        &selection.implementation,
                        &selection.review,
                    ];
                    let missing = chosen.into_iter().find(|agent| {
                        !snapshot.connections["agents"]
                            .as_array()
                            .is_some_and(|entries| {
                                entries.iter().any(|e| {
                                    e["id"].as_str() == Some(agent.as_str())
                                        && e["prepared"] == true
                                })
                            })
                    });
                    if let Some(agent) = missing {
                        pending = Some((format!("Prepare the existing {agent} integration using its supported login?"), Action::Connect { agent: agent.clone() }));
                    } else {
                        message = "All selected agents are prepared. Press i to initialize.".into();
                    }
                }
                KeyCode::Char('b') if connected => commands.send(Command::Browser)?,
                _ => (),
            }
            continue;
        }
        match key.code {
            KeyCode::Char('1') => { view = "mission".into(); scroll = 0; },
            KeyCode::Char('2') => { view = "decisions".into(); scroll = 0; },
            KeyCode::Char('3') => { view = "candidate".into(); scroll = 0; },
            KeyCode::Char('4') => { view = "events".into(); selected = 0; scroll = 0; },
            KeyCode::Down => { selected = selected.saturating_add(1); scroll = 0; },
            KeyCode::Up => { selected = selected.saturating_sub(1); scroll = 0; },
            KeyCode::PageDown => scroll = scroll.saturating_add(8),
            KeyCode::PageUp => scroll = scroll.saturating_sub(8),
            KeyCode::Char('b') if connected => commands.send(Command::Browser)?,
            KeyCode::Char('r') if ready => {
                let interrupted = state.as_ref().is_some_and(|s| s.state["phase"] == "interrupted");
                pending = Some(("Run or reconcile the existing mission? Native work uses your selected account.".into(), if interrupted { Action::Resume } else { Action::Run }));
            }
            KeyCode::Char('x') if ready => pending = Some(("Run the isolated boundary and recovery exercise? Your working mission allowance is preserved.".into(), Action::Exercise)),
            KeyCode::Char('a') if ready && view == "candidate" => {
                if let Some(candidate) = state.as_ref().and_then(|s| s.state["proposal"]["candidate_sha256"].as_str()) {
                    pending = Some((format!("Publish this exact reviewed candidate locally?\n{candidate}"), Action::Approve { candidate: candidate.into() }));
                }
            }
            KeyCode::Char('a') => message = "Open candidate review (3), inspect source and test evidence, then press a.".into(),
            _ => (),
        }
    }
    Ok(())
}

fn cycle(agent: &mut String) {
    *agent = match agent.as_str() {
        "hermes" => "codex",
        "codex" => "pi",
        "pi" => "claude",
        _ => "hermes",
    }
    .into();
}

fn setup(frame: &mut Frame, area: Rect, snapshot: &Snapshot, selection: &Selection, accent: Color) {
    let mut text = format!("Build a system of agents.\n\nChoose your native agents. Each swarm has a coordinator and two assignments.\n\n1  Research        {}\n2  Implementation  {}\n3  Review          {}\n\nh  All Hermes    m  Hermes → Codex → Pi\n\nc  Prepare next selected agent    i  Create mission\n\nConnections\n", selection.research, selection.implementation, selection.review);
    for agent in snapshot.connections["agents"]
        .as_array()
        .into_iter()
        .flatten()
    {
        text.push_str(&format!(
            "{} · {}\n",
            agent["name"].as_str().unwrap_or("agent"),
            if agent["prepared"] == true {
                "prepared"
            } else {
                "not prepared"
            }
        ));
    }
    text.push_str("\nChio supplies authority and execution rules. The host retains credentials.\nHerdr operates the workspace. Native workers perform the mission.\n\nChoose Claude Code, Hermes, Codex, or Pi for any role.");
    frame.render_widget(
        Paragraph::new(client::text(&text))
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::TOP)
                    .border_style(Style::default().fg(accent)),
            ),
        area,
    );
}

fn mission(frame: &mut Frame, area: Rect, snapshot: &Snapshot, accent: Color) {
    let state = &snapshot.state;
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(5),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(format!(
            "{}\n{}{}",
            state["mission"].as_str().unwrap_or("Mission"),
            state["phase"].as_str().unwrap_or("unknown"),
            if snapshot.busy {
                " · host operation running"
            } else {
                ""
            }
        )),
        rows[0],
    );
    let layout = if area.width >= 96 {
        Layout::horizontal([Constraint::Ratio(1, 3); 3])
    } else {
        Layout::vertical([Constraint::Ratio(1, 3); 3])
    };
    let panels = layout.split(rows[1]);
    for (index, role) in ["research", "implementation", "review"].iter().enumerate() {
        let agent = state["agents"][role].as_str().unwrap_or("reference worker");
        let outcomes = state["outcomes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|o| {
                o["assignment"]["worker"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(role))
            })
            .count();
        let mut content = format!("▪  ▪\n{agent}\n{outcomes}/2 assignments retained\n\n");
        for event in state["events"]
            .as_array()
            .into_iter()
            .flatten()
            .rev()
            .filter(|e| e["actor"].as_str().is_some_and(|a| a.starts_with(role)))
            .take(3)
        {
            content.push_str(&format!(
                "{} · {}\n",
                event["sequence"],
                event["kind"].as_str().unwrap_or("event")
            ));
        }
        content.push_str("\nNative operations\n");
        for call in state["native_calls"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["worker"].as_str().is_some_and(|w| w.starts_with(role)))
            .rev()
            .take(4)
        {
            content.push_str(&format!(
                "{} · {}\n",
                call["tool"].as_str().unwrap_or("operation"),
                call["state"].as_str().unwrap_or("retained")
            ));
        }
        for outcome in state["outcomes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|o| {
                o["assignment"]["worker"]
                    .as_str()
                    .is_some_and(|w| w.starts_with(role))
            })
            .take(1)
        {
            let answer = &outcome["output"]["result"]["answer"];
            if let Some(findings) = answer["findings"].as_array() {
                content.push_str("\nRetained findings\n");
                for finding in findings.iter().take(2) {
                    let description = finding["description"]
                        .as_str()
                        .or_else(|| finding["id"].as_str())
                        .unwrap_or("Finding retained");
                    content.push_str(&description.chars().take(180).collect::<String>());
                    content.push_str("\n\n");
                }
            }
        }
        frame.render_widget(
            Paragraph::new(client::text(&content))
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::TOP)
                        .title(format!(" {role} "))
                        .border_style(Style::default().fg(accent)),
                ),
            panels[index],
        );
    }
    let count = state["native_calls"].as_array().map_or(0, Vec::len);
    let capacity = if state["capacity"].is_object() {
        format!(
            "Shared allowance · {} / {} remaining · {} committed · {} reserved",
            state["capacity"]["remaining"],
            state["capacity"]["total"],
            state["capacity"]["committed"],
            state["capacity"]["reserved"]
        )
    } else {
        "Shared allowance · awaiting authoritative observation".into()
    };
    frame.render_widget(Paragraph::new(format!("Chio kernel · {count} native operation observations\n{}\nPublication · {}\nNative activity views · inspect original receipts with 2", client::text(&capacity), if state["published"] == true { "exact candidate published locally" } else { "owner approval required" }))
        .wrap(Wrap { trim: false }).block(Block::default().borders(Borders::TOP).border_style(Style::default().fg(accent))), rows[2]);
}

fn detail(snapshot: &Snapshot, view: &str, selected: usize) -> String {
    let state = &snapshot.state;
    if view == "events" {
        let events = state["events"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        if events.is_empty() {
            return "No retained host events yet.".into();
        }
        let index = events.len() - 1 - selected.min(events.len() - 1);
        return format!("Host event {} of {} · newest first\nApplication observations retain readiness, handoffs, and isolated exercise checks.\nOriginal signed kernel receipts are available in Decisions.\n\n{}", index+1, events.len(), pretty(&events[index]));
    }
    if view == "candidate" {
        let reviews: Vec<_> = state["outcomes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|o| {
                o["assignment"]["worker"]
                    .as_str()
                    .is_some_and(|w| w.starts_with("review"))
            })
            .collect();
        return format!("Original source\n{}\n\nCandidate source\n{}\n\nExact proposal\n{}\n\nIndependent review and test evidence\n{}\n\nPress a only after reviewing this candidate. Publication is local.", state["original"].as_str().unwrap_or(""), state["candidate"].as_str().unwrap_or("No candidate yet"), pretty(&state["proposal"]), serde_json::to_string_pretty(&reviews).unwrap_or_default());
    }
    let native = state["native_calls"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let outcomes = state["outcomes"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let all: Vec<_> = native.iter().chain(outcomes).collect();
    if all.is_empty() {
        return "No retained operations yet. An idle agent does not establish a completed operation.".into();
    }
    let index = selected.min(all.len() - 1);
    format!("Operation {} of {}\nNative observations and mission outcomes retain their original identities.\nInspect request, authority reference, result, and original receipt below.\n\n{}", index+1, all.len(), format_args!("{}\n\nWorker authority (public projection)\n{}", pretty(all[index]), pretty(&state["authority"]["workers"])))
}
fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

#[cfg(test)]
mod role_tests {
    #[test]
    fn setup_cycles_through_all_four_native_agents() {
        let mut agent = "hermes".to_owned();
        for expected in ["codex", "pi", "claude", "hermes"] {
            super::cycle(&mut agent);
            assert_eq!(agent, expected);
        }
    }
}
