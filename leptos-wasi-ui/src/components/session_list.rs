use leptos::prelude::*;

const DEFAULT_CONTAINER_CLASS: &str = "wasi-auth-session-list";
const DEFAULT_CONTAINER_STYLE: &str = "\
    background: rgba(17, 24, 39, 0.7); \
    backdrop-filter: blur(16px); \
    -webkit-backdrop-filter: blur(16px); \
    border: 1px solid rgba(255, 255, 255, 0.08); \
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3); \
    border-radius: 12px; \
    padding: 24px; \
    color: #f9fafb; \
    font-family: sans-serif; \
    max-width: 600px; \
    width: 100%; \
    box-sizing: border-box;";

const DEFAULT_ITEM_CLASS: &str = "wasi-auth-session-item";
const DEFAULT_ITEM_STYLE: &str = "\
    display: flex; \
    justify-content: space-between; \
    align-items: center; \
    padding: 14px 16px; \
    border: 1px solid rgba(255, 255, 255, 0.05); \
    margin-bottom: 12px; \
    border-radius: 8px; \
    background: rgba(255, 255, 255, 0.02); \
    transition: all 0.2s ease-in-out;";

const CURRENT_ITEM_STYLE: &str = "\
    background: rgba(16, 185, 129, 0.04); \
    border-color: rgba(16, 185, 129, 0.25);";

const ROLE_BADGE_STYLE: &str = "\
    background: rgba(255, 255, 255, 0.08); \
    color: rgba(255, 255, 255, 0.85); \
    border: 1px solid rgba(255, 255, 255, 0.1); \
    border-radius: 9999px; \
    padding: 2px 8px; \
    font-size: 11px; \
    font-weight: 500; \
    text-transform: uppercase; \
    letter-spacing: 0.05em; \
    margin-right: 4px; \
    margin-top: 4px;";

const CURRENT_BADGE_STYLE: &str = "\
    background: rgba(16, 185, 129, 0.15); \
    color: #34d399; \
    border: 1px solid rgba(16, 185, 129, 0.3); \
    border-radius: 9999px; \
    padding: 2px 8px; \
    font-size: 11px; \
    font-weight: 600;";

const REVOKE_BUTTON_CLASS: &str = "wasi-auth-revoke-button";
const REVOKE_BUTTON_STYLE: &str = "\
    background: rgba(239, 68, 68, 0.15); \
    border: 1px solid rgba(239, 68, 68, 0.25); \
    border-radius: 6px; \
    padding: 6px 12px; \
    color: #f87171; \
    cursor: pointer; \
    transition: all 0.2s ease-in-out; \
    font-weight: 500; \
    font-size: 12px; \
    display: inline-flex; \
    align-items: center; \
    justify-content: center;";

const REVOKE_ALL_BUTTON_CLASS: &str = "wasi-auth-revoke-all-button";
const REVOKE_ALL_BUTTON_STYLE: &str = "\
    background: rgba(255, 255, 255, 0.05); \
    border: 1px solid rgba(255, 255, 255, 0.1); \
    border-radius: 6px; \
    padding: 10px 16px; \
    color: rgba(255, 255, 255, 0.8); \
    cursor: pointer; \
    transition: all 0.2s ease-in-out; \
    font-weight: 500; \
    width: 100%; \
    display: flex; \
    align-items: center; \
    justify-content: center; \
    gap: 8px; \
    margin-top: 16px; \
    font-size: 13px;";

fn format_timestamp(mut secs: u64) -> String {
    if secs > 253402300799 {
        secs = 253402300799;
    }
    let days = secs / 86400;
    let seconds_in_day = secs % 86400;
    let hours = seconds_in_day / 3600;
    let minutes = (seconds_in_day % 3600) / 60;
    let seconds = seconds_in_day % 60;

    let mut year = 1970;
    let mut days_left = days;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days_left < days_in_year {
            break;
        }
        days_left -= days_in_year;
        year += 1;
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for &d in month_days.iter() {
        if days_left < d {
            break;
        }
        days_left -= d;
        month += 1;
    }
    let day = days_left + 1;
    format!(
        "Expires: {:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hours, minutes, seconds
    )
}

/// A list component for managing active user sessions.
///
/// Renders active sessions along with metadata (expiry, roles) and highlights
/// the current browser session. Enables revoking a single session or revoking all
/// other sessions in bulk if the `on_revoke_all` callback is supplied.
#[component]
pub fn SessionList(
    #[prop(optional, into)] class: Option<TextProp>,
    #[prop(optional, into)] style: Option<TextProp>,

    /// List of sessions to display
    #[prop(into)]
    sessions: Signal<Vec<wasi_auth_traits::Session>>,
    /// Unique identifier of the current active browser session
    #[prop(into, optional)]
    current_session_id: Option<Signal<Option<String>>>,

    /// Revocation callback for single sessions
    on_revoke: Callback<String>,
    /// Revocation callback for other sessions (bulk)
    #[prop(optional)]
    on_revoke_all: Option<Callback<()>>,

    /// Signals for tracking active operations and outcomes
    #[prop(into)]
    revoke_pending: Signal<bool>,
    #[prop(into)] revoke_result: Signal<Option<Result<(), String>>>,

    /// Style override flag
    #[prop(optional, default = true)]
    use_default_styles: bool,
) -> impl IntoView {
    let merged_class = move || {
        let user_class = class
            .as_ref()
            .map(|c| format!(" {}", c.get()))
            .unwrap_or_default();
        format!("{}{}", DEFAULT_CONTAINER_CLASS, user_class)
    };

    let merged_style = move || {
        if use_default_styles {
            let user_style = style
                .as_ref()
                .map(|s| format!("; {}", s.get()))
                .unwrap_or_default();
            format!("{}{}", DEFAULT_CONTAINER_STYLE, user_style)
        } else {
            style
                .as_ref()
                .map(|s| s.get().to_string())
                .unwrap_or_default()
        }
    };

    let item_style_for = move |is_current: bool| {
        if use_default_styles {
            if is_current {
                format!("{} {}", DEFAULT_ITEM_STYLE, CURRENT_ITEM_STYLE)
            } else {
                DEFAULT_ITEM_STYLE.to_string()
            }
        } else {
            "".to_string()
        }
    };

    let button_style = move || {
        if use_default_styles {
            REVOKE_BUTTON_STYLE
        } else {
            ""
        }
    };

    let bulk_button_style = move || {
        if use_default_styles {
            REVOKE_ALL_BUTTON_STYLE
        } else {
            ""
        }
    };

    let header_style = move || {
        if use_default_styles {
            "margin-top: 0; margin-bottom: 8px; font-size: 20px; font-weight: 600;"
        } else {
            ""
        }
    };

    let subtitle_style = move || {
        if use_default_styles {
            "margin-top: 0; margin-bottom: 20px; font-size: 14px; color: rgba(255, 255, 255, 0.6);"
        } else {
            ""
        }
    };

    let empty_box_style = move || {
        if use_default_styles {
            "padding: 24px; text-align: center; color: rgba(255, 255, 255, 0.4); font-size: 14px; border: 1px dashed rgba(255, 255, 255, 0.1); border-radius: 8px;"
        } else {
            ""
        }
    };

    let success_box_style = move || {
        if use_default_styles {
            "margin-top: 16px; padding: 10px 12px; border-radius: 6px; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); color: #34d399; font-size: 13px; text-align: center;"
        } else {
            ""
        }
    };

    let error_box_style = move || {
        if use_default_styles {
            "margin-top: 16px; padding: 10px 12px; border-radius: 6px; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: #f87171; font-size: 13px; text-align: center;"
        } else {
            ""
        }
    };

    view! {
        <div class=merged_class style=merged_style>
            {if use_default_styles {
                Some(view! {
                    <style>
                        {r#"
                        .wasi-auth-session-item:hover {
                            background: rgba(255, 255, 255, 0.04) !important;
                            border-color: rgba(255, 255, 255, 0.08) !important;
                        }
                        .wasi-auth-session-item.is-current:hover {
                            background: rgba(16, 185, 129, 0.06) !important;
                            border-color: rgba(16, 185, 129, 0.3) !important;
                        }
                        .wasi-auth-revoke-button:hover:not(:disabled) {
                            background: rgba(239, 68, 68, 0.25) !important;
                            border-color: rgba(239, 68, 68, 0.4) !important;
                            color: #fff !important;
                        }
                        .wasi-auth-revoke-button:disabled {
                            opacity: 0.5;
                            cursor: not-allowed;
                        }
                        .wasi-auth-revoke-all-button:hover:not(:disabled) {
                            background: rgba(255, 255, 255, 0.08) !important;
                            border-color: rgba(255, 255, 255, 0.18) !important;
                            color: #fff !important;
                        }
                        .wasi-auth-revoke-all-button:disabled {
                            opacity: 0.5;
                            cursor: not-allowed;
                        }
                        "#}
                    </style>
                })
            } else {
                None
            }}

            <h2 style=header_style>"Active Sessions"</h2>
            <p style=subtitle_style>"Manage your logged-in sessions on various devices."</p>

            {move || {
                let session_list = sessions.get();
                if session_list.is_empty() {
                    view! {
                        <div style=empty_box_style>
                            "No active sessions found."
                        </div>
                    }.into_any()
                } else {
                    view! {
                        <div style="display: flex; flex-direction: column;">
                            <For
                                each=move || sessions.get()
                                key=|s| s.session_id.clone()
                                children=move |s| {
                                    let session_id_val = s.session_id.clone();
                                    let session_id_val_for_revoke = s.session_id.clone();
                                    let session_id_val_for_current = s.session_id.clone();
                                    let is_current = move || {
                                        current_session_id
                                            .map(|cur| cur.with(|c| c.as_ref() == Some(&session_id_val_for_current)))
                                            .unwrap_or(false)
                                    };
                                    let is_current_for_class = is_current.clone();
                                    let is_current_for_style = is_current.clone();
                                    let is_current_for_badge = is_current;

                                    let item_class = move || {
                                        if is_current_for_class() {
                                            format!("{} is-current", DEFAULT_ITEM_CLASS)
                                        } else {
                                            DEFAULT_ITEM_CLASS.to_string()
                                        }
                                    };

                                    let on_revoke_click = {
                                        let on_revoke = on_revoke;
                                        move |_| {
                                            if !revoke_pending.get() {
                                                on_revoke.run(session_id_val_for_revoke.clone());
                                            }
                                        }
                                    };

                                    let truncated_id = if session_id_val.chars().count() > 8 {
                                        format!("{}...", session_id_val.chars().take(8).collect::<String>())
                                    } else {
                                        session_id_val.clone()
                                    };

                                    let expires_str = format_timestamp(s.expires_at);

                                    view! {
                                        <div class=item_class style=move || item_style_for(is_current_for_style())>
                                            <div style="display: flex; flex-direction: column; gap: 4px;">
                                                <div style="font-weight: 600; font-size: 14px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                                                    "ID: " {truncated_id}
                                                    {move || if is_current_for_badge() { Some(view! { <span style=CURRENT_BADGE_STYLE>"Current"</span> }) } else { None }}
                                                </div>
                                                <div style="font-size: 12px; color: rgba(255, 255, 255, 0.5);">
                                                    {expires_str}
                                                </div>
                                                <div style="display: flex; flex-wrap: wrap; margin-top: 4px;">
                                                    {s.roles.iter().map(|role| view! {
                                                        <span style=ROLE_BADGE_STYLE>{role.to_uppercase()}</span>
                                                    }).collect::<Vec<_>>()}
                                                </div>
                                            </div>

                                            <button
                                                type="button"
                                                class=REVOKE_BUTTON_CLASS
                                                style=button_style
                                                disabled=revoke_pending
                                                on:click=on_revoke_click
                                            >
                                                "Revoke"
                                            </button>
                                        </div>
                                    }
                                }
                            />
                        </div>
                    }.into_any()
                }
            }}

            {move || {
                let session_list = sessions.get();
                // Render "Revoke All Other Sessions" only if there are multiple sessions and bulk revoke callback is provided
                if let Some(ref cb) = on_revoke_all {
                    let has_others = current_session_id
                        .map(|cur| {
                            cur.with(|c| {
                                session_list.iter().any(|s| Some(&s.session_id) != c.as_ref())
                            })
                        })
                        .unwrap_or(!session_list.is_empty());

                    if has_others {
                        let on_revoke_all_click = {
                            let cb = *cb;
                            move |_| {
                                if !revoke_pending.get() {
                                    cb.run(());
                                }
                            }
                        };
                        Some(view! {
                            <button
                                type="button"
                                class=REVOKE_ALL_BUTTON_CLASS
                                style=bulk_button_style
                                disabled=revoke_pending
                                on:click=on_revoke_all_click
                            >
                                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 16px; height: 16px;" xmlns="http://www.w3.org/2000/svg">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                </svg>
                                "Revoke All Other Sessions"
                            </button>
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }}

            {move || {
                revoke_result.with(|res| {
                    res.as_ref().map(|inner| {
                        match inner {
                            Ok(_) => view! {
                                <div style=success_box_style>
                                    "Session revoked successfully."
                                </div>
                            }.into_any(),
                            Err(err) => view! {
                                <div style=error_box_style>
                                    {err.clone()}
                                </div>
                            }.into_any()
                        }
                    })
                })
            }}
        </div>
    }
}
