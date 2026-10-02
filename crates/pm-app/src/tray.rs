//! System tray icon with a small menu (Windows).

use std::sync::mpsc::{Receiver, channel};

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::icon::icon_rgba;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    Show,
    Toggle,
    Quit,
}

pub struct Tray {
    icon: TrayIcon,
    toggle: MenuItem,
    commands: Receiver<TrayCommand>,
    running: Option<bool>,
}

fn make_icon(active: bool) -> anyhow::Result<Icon> {
    const SIZE: u32 = 32;
    Ok(Icon::from_rgba(icon_rgba(SIZE, active), SIZE, SIZE)?)
}

impl Tray {
    /// Creates the tray icon. Events wake up the UI through `ctx`, even while the window is hidden.
    pub fn new(ctx: eframe::egui::Context) -> anyhow::Result<Self> {
        let menu = Menu::new();
        let show = MenuItem::new("Открыть", true, None);
        let toggle = MenuItem::new("Запустить", true, None);
        let quit = MenuItem::new("Выход", true, None);
        menu.append_items(&[&show, &toggle, &PredefinedMenuItem::separator(), &quit])?;

        let (tx, commands) = channel();
        let (show_id, toggle_id, quit_id) =
            (show.id().clone(), toggle.id().clone(), quit.id().clone());
        {
            let (tx, ctx) = (tx.clone(), ctx.clone());
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                let cmd = if event.id == show_id {
                    TrayCommand::Show
                } else if event.id == toggle_id {
                    TrayCommand::Toggle
                } else if event.id == quit_id {
                    TrayCommand::Quit
                } else {
                    return;
                };
                let _ = tx.send(cmd);
                ctx.request_repaint();
            }));
        }
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            let show = matches!(
                event,
                TrayIconEvent::DoubleClick { .. }
                    | TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
            );
            if show {
                let _ = tx.send(TrayCommand::Show);
                ctx.request_repaint();
            }
        }));

        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_tooltip("Proxy Manager")
            .with_icon(make_icon(false)?)
            .build()?;
        Ok(Self {
            icon,
            toggle,
            commands,
            running: None,
        })
    }

    pub fn poll(&self) -> Vec<TrayCommand> {
        self.commands.try_iter().collect()
    }

    /// Updates the icon, tooltip and menu to reflect the proxying state.
    pub fn set_running(&mut self, running: bool) {
        if self.running == Some(running) {
            return;
        }
        self.running = Some(running);
        self.toggle.set_text(if running {
            "Остановить"
        } else {
            "Запустить"
        });
        if let Ok(icon) = make_icon(running) {
            let _ = self.icon.set_icon(Some(icon));
        }
        let tooltip = if running {
            "Proxy Manager — работает"
        } else {
            "Proxy Manager — остановлен"
        };
        let _ = self.icon.set_tooltip(Some(tooltip));
    }
}
