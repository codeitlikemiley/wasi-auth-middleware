#![cfg(feature = "passkey")]

use leptos::prelude::*;

fn format_date(timestamp_ms: i64) -> String {
    let secs = if timestamp_ms < 0 {
        0
    } else if timestamp_ms > 253402300799000 {
        253402300799
    } else {
        (timestamp_ms / 1000) as u64
    };
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
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hours, minutes, seconds
    )
}

/// A list component showing the user's registered passkeys (requires the `passkey` feature).
///
/// Provides inline controls for renaming passkeys (via `on_rename` callback)
/// and deleting/revoking passkeys (via `on_delete` callback). Supports confirmation flows
/// and displays operation results dynamically.
#[component]
pub fn PasskeyList(
    #[prop(optional, into)] class: Option<TextProp>,
    #[prop(optional, into)] style: Option<TextProp>,
    /// The reactive signal providing the user's registered passkeys.
    #[prop(into)]
    passkeys: Signal<Vec<wasi_auth_core::passkey::StoredPasskey>>,
    /// Callback triggered when a passkey deletion is confirmed. Returns the `cred_id`.
    on_delete: Callback<String>,
    /// Callback triggered when a passkey rename is saved. Returns `(cred_id, new_name)`.
    on_rename: Callback<(String, String)>,
    /// Optional global loading/pending state.
    #[prop(into, optional)]
    pending: Option<Signal<bool>>,
    /// If true, inject the default premium glassmorphism styling.
    #[prop(optional, default = true)]
    use_default_styles: bool,
    #[prop(into, optional)] rename_result: Option<Signal<Option<Result<(), String>>>>,
    #[prop(into, optional)] delete_result: Option<Signal<Option<Result<(), String>>>>,
) -> impl IntoView {
    let (editing_id, set_editing_id) = leptos::prelude::signal(None::<String>);
    let (rename_name, set_rename_name) = leptos::prelude::signal(String::new());
    let (confirm_delete_id, set_confirm_delete_id) = leptos::prelude::signal(None::<String>);

    let is_pending = move || pending.map(|p| p.get()).unwrap_or(false);

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

    let merged_class = move || {
        let user_class = class
            .as_ref()
            .map(|c| format!(" {}", c.get()))
            .unwrap_or_default();
        format!("wasi-auth-passkey-list{}", user_class)
    };

    let merged_style = move || {
        if use_default_styles {
            let user_style = style
                .as_ref()
                .map(|s| format!("; {}", s.get()))
                .unwrap_or_default();
            format!(
                "background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3), 0 10px 10px -5px rgba(0, 0, 0, 0.3); border-radius: 12px; padding: 24px; color: #f9fafb; font-family: sans-serif; max-width: 500px; width: 100%; box-sizing: border-box;{}",
                user_style
            )
        } else {
            style
                .as_ref()
                .map(|s| s.get().to_string())
                .unwrap_or_default()
        }
    };

    view! {
        <div class=merged_class style=merged_style>
            {if use_default_styles {
                Some(view! {
                    <style>
                        {r#"
                        .wasi-auth-passkey-list {
                            margin: 0 auto;
                        }
                        .wasi-auth-passkey-items {
                            display: flex;
                            flex-direction: column;
                            transition: opacity 0.2s ease-in-out;
                        }
                        .wasi-auth-passkey-item {
                            display: flex;
                            align-items: center;
                            justify-content: space-between;
                            padding: 12px 16px;
                            background: rgba(255, 255, 255, 0.03);
                            border: 1px solid rgba(255, 255, 255, 0.06);
                            border-radius: 8px;
                            margin-bottom: 12px;
                            transition: all 0.2s ease-in-out;
                        }
                        .wasi-auth-passkey-item:hover {
                            background: rgba(255, 255, 255, 0.06);
                            border-color: rgba(255, 255, 255, 0.1);
                        }
                        .wasi-auth-passkey-item-left {
                            display: flex;
                            align-items: center;
                            gap: 12px;
                            flex: 1;
                            min-width: 0;
                        }
                        .wasi-auth-passkey-icon-container {
                            background: rgba(255, 255, 255, 0.05);
                            border: 1px solid rgba(255, 255, 255, 0.08);
                            border-radius: 6px;
                            padding: 8px;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            color: rgba(255, 255, 255, 0.7);
                            flex-shrink: 0;
                        }
                        .wasi-auth-passkey-info {
                            display: flex;
                            flex-direction: column;
                            min-width: 0;
                            flex: 1;
                        }
                        .wasi-auth-passkey-name {
                            font-size: 14px;
                            font-weight: 500;
                            color: #fff;
                            white-space: nowrap;
                            overflow: hidden;
                            text-overflow: ellipsis;
                        }
                        .wasi-auth-passkey-meta {
                            font-size: 11px;
                            color: rgba(255, 255, 255, 0.4);
                            margin-top: 2px;
                        }
                        .wasi-auth-passkey-actions {
                            display: flex;
                            align-items: center;
                            gap: 8px;
                            flex-shrink: 0;
                        }
                        .wasi-auth-passkey-input {
                            background: rgba(255, 255, 255, 0.05);
                            border: 1px solid rgba(255, 255, 255, 0.15);
                            border-radius: 6px;
                            padding: 6px 10px;
                            color: #fff;
                            font-size: 14px;
                            outline: none;
                            width: 100%;
                            box-sizing: border-box;
                            transition: all 0.2s;
                        }
                        .wasi-auth-passkey-input:focus {
                            border-color: rgba(255, 255, 255, 0.3) !important;
                            background: rgba(255, 255, 255, 0.08) !important;
                            box-shadow: 0 0 0 2px rgba(255, 255, 255, 0.05);
                        }
                        .wasi-auth-passkey-btn {
                            background: transparent;
                            border: 1px solid transparent;
                            border-radius: 6px;
                            cursor: pointer;
                            display: inline-flex;
                            align-items: center;
                            justify-content: center;
                            padding: 6px;
                            transition: all 0.2s ease-in-out;
                            color: rgba(255, 255, 255, 0.6);
                        }
                        .wasi-auth-passkey-btn:hover {
                            color: #fff;
                            background: rgba(255, 255, 255, 0.08);
                            border-color: rgba(255, 255, 255, 0.1);
                        }
                        .wasi-auth-passkey-btn-danger {
                            color: #f87171;
                            background: rgba(239, 68, 68, 0.1);
                            border-color: rgba(239, 68, 68, 0.2);
                        }
                        .wasi-auth-passkey-btn-danger:hover {
                            color: #fff;
                            background: rgba(239, 68, 68, 0.25) !important;
                            border-color: rgba(239, 68, 68, 0.4) !important;
                        }
                        .wasi-auth-passkey-btn-secondary {
                            color: rgba(255, 255, 255, 0.5);
                            border: 1px solid rgba(255, 255, 255, 0.1);
                        }
                        .wasi-auth-passkey-btn-secondary:hover {
                            color: rgba(255, 255, 255, 0.9);
                            background: rgba(255, 255, 255, 0.06);
                            border-color: rgba(255, 255, 255, 0.2);
                        }
                        .wasi-auth-passkey-empty {
                            text-align: center;
                            padding: 32px 16px;
                            color: rgba(255, 255, 255, 0.5);
                            font-size: 14px;
                            border: 1px dashed rgba(255, 255, 255, 0.1);
                            border-radius: 8px;
                            background: rgba(255, 255, 255, 0.01);
                        }
                        "#}
                    </style>
                })
            } else {
                None
            }}

            <h3 style=move || if use_default_styles { "margin-top: 0; margin-bottom: 16px; font-size: 18px; font-weight: 600;" } else { "" }>
                "Registered Passkeys"
            </h3>

            {move || {
                let current_passkeys = passkeys.get();
                if current_passkeys.is_empty() {
                    view! {
                        <div class="wasi-auth-passkey-empty">
                            "No registered passkeys yet. Add a passkey to secure your account."
                        </div>
                    }.into_any()
                } else {
                    view! {
                        <div class="wasi-auth-passkey-items" style=move || if is_pending() { "opacity: 0.6; pointer-events: none;" } else { "" }>
                            <For
                                each=move || passkeys.get()
                                key=|pk| pk.cred_id.clone()
                                children=move |pk| {
                                    let cred_id = pk.cred_id.clone();
                                    let name = pk.name.clone();
                                    let created_at = pk.created_at;
                                    let last_used_at = pk.last_used_at;

                                    let is_editing = {
                                        let cred_id = cred_id.clone();
                                        move || editing_id.with(|id| id.as_ref() == Some(&cred_id))
                                    };
                                    let is_editing_for_view = is_editing.clone();

                                    let is_confirming_delete = {
                                        let cred_id = cred_id.clone();
                                        move || confirm_delete_id.with(|id| id.as_ref() == Some(&cred_id))
                                    };

                                    let formatted_created = format_date(created_at);
                                    let formatted_used = if last_used_at > 0 {
                                        format_date(last_used_at)
                                    } else {
                                        "Never".to_string()
                                    };

                                    view! {
                                        <div class="wasi-auth-passkey-item">
                                            <div class="wasi-auth-passkey-item-left">
                                                <div class="wasi-auth-passkey-icon-container">
                                                    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 20px; height: 20px;" xmlns="http://www.w3.org/2000/svg">
                                                        <path stroke-linecap="round" stroke-linejoin="round" d="M15 7a2 2 0 012 2m-2 4a5 5 0 11-4-4 1.9 1.9 0 011 0M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                                    </svg>
                                                </div>
                                                <div class="wasi-auth-passkey-info">
                                                    {
                                                        let cred_id = cred_id.clone();
                                                        let name = name.clone();
                                                        move || if is_editing_for_view() {
                                                            let cred_id = cred_id.clone();
                                                            view! {
                                                                <div style="display: flex; gap: 8px; width: 100%;">
                                                                    <input
                                                                        type="text"
                                                                        class="wasi-auth-passkey-input"
                                                                        prop:value=rename_name
                                                                        disabled=is_pending
                                                                        on:input=move |ev| set_rename_name.set(event_target_value(&ev))
                                                                        on:keydown=move |ev| {
                                                                            if ev.key() == "Enter" {
                                                                                let new_name = rename_name.get();
                                                                                if !new_name.trim().is_empty() {
                                                                                    on_rename.run((cred_id.clone(), new_name));
                                                                                }
                                                                                set_editing_id.set(None);
                                                                            } else if ev.key() == "Escape" {
                                                                                set_editing_id.set(None);
                                                                            }
                                                                        }
                                                                        autofocus
                                                                    />
                                                                </div>
                                                            }.into_any()
                                                        } else {
                                                            let name = name.clone();
                                                            view! {
                                                                <div class="wasi-auth-passkey-name">
                                                                    {name.clone()}
                                                                </div>
                                                            }.into_any()
                                                        }
                                                    }
                                                    <div class="wasi-auth-passkey-meta">
                                                        <span>"Added: " {formatted_created.clone()}</span>
                                                        <span style="margin: 0 6px;">"•"</span>
                                                        <span>"Last used: " {formatted_used.clone()}</span>
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="wasi-auth-passkey-actions">
                                                {
                                                    let cred_id = cred_id.clone();
                                                    let name = name.clone();
                                                    move || if is_editing() {
                                                        let cred_id = cred_id.clone();
                                                        view! {
                                                            <div style="display: flex; gap: 4px;">
                                                                <button
                                                                    type="button"
                                                                    class="wasi-auth-passkey-btn"
                                                                    style="color: #34d399;"
                                                                    disabled=is_pending
                                                                    on:click=move |_ev: leptos::ev::MouseEvent| {
                                                                        let new_name = rename_name.get();
                                                                        if !new_name.trim().is_empty() {
                                                                            on_rename.run((cred_id.clone(), new_name));
                                                                        }
                                                                        set_editing_id.set(None);
                                                                    }
                                                                    title="Save Rename"
                                                                >
                                                                    <svg fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24" style="width: 16px; height: 16px;" xmlns="http://www.w3.org/2000/svg">
                                                                        <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                                                                    </svg>
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    class="wasi-auth-passkey-btn wasi-auth-passkey-btn-secondary"
                                                                    disabled=is_pending
                                                                    on:click=move |_ev: leptos::ev::MouseEvent| {
                                                                        set_editing_id.set(None);
                                                                    }
                                                                    title="Cancel Edit"
                                                                >
                                                                    <svg fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24" style="width: 16px; height: 16px;" xmlns="http://www.w3.org/2000/svg">
                                                                        <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
                                                                    </svg>
                                                                </button>
                                                            </div>
                                                        }.into_any()
                                                    } else if is_confirming_delete() {
                                                        let cred_id = cred_id.clone();
                                                        view! {
                                                            <div style="display: flex; align-items: center; gap: 6px;">
                                                                <button
                                                                    type="button"
                                                                    class="wasi-auth-passkey-btn wasi-auth-passkey-btn-danger"
                                                                    style="padding: 4px 8px; font-size: 11px; font-weight: 500;"
                                                                    disabled=is_pending
                                                                    on:click=move |_ev: leptos::ev::MouseEvent| {
                                                                        on_delete.run(cred_id.clone());
                                                                        set_confirm_delete_id.set(None);
                                                                    }
                                                                >
                                                                    "Confirm"
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    class="wasi-auth-passkey-btn wasi-auth-passkey-btn-secondary"
                                                                    style="padding: 4px 8px; font-size: 11px;"
                                                                    disabled=is_pending
                                                                    on:click=move |_ev: leptos::ev::MouseEvent| {
                                                                        set_confirm_delete_id.set(None);
                                                                    }
                                                                >
                                                                    "Cancel"
                                                                </button>
                                                            </div>
                                                        }.into_any()
                                                    } else {
                                                        let cred_id_for_edit = cred_id.clone();
                                                        let cred_id_for_delete = cred_id.clone();
                                                        let name = name.clone();
                                                        view! {
                                                            <div style="display: flex; gap: 4px;">
                                                                <button
                                                                    type="button"
                                                                    class="wasi-auth-passkey-btn"
                                                                    disabled=is_pending
                                                                    on:click=move |_ev: leptos::ev::MouseEvent| {
                                                                        set_editing_id.set(Some(cred_id_for_edit.clone()));
                                                                        set_rename_name.set(name.clone());
                                                                        set_confirm_delete_id.set(None);
                                                                    }
                                                                    title="Rename Passkey"
                                                                >
                                                                    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 16px; height: 16px;" xmlns="http://www.w3.org/2000/svg">
                                                                        <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487zm0 0L19.5 7.125" />
                                                                    </svg>
                                                                </button>
                                                                <button
                                                                    type="button"
                                                                    class="wasi-auth-passkey-btn wasi-auth-passkey-btn-danger"
                                                                    disabled=is_pending
                                                                    on:click=move |_ev: leptos::ev::MouseEvent| {
                                                                        set_confirm_delete_id.set(Some(cred_id_for_delete.clone()));
                                                                        set_editing_id.set(None);
                                                                    }
                                                                    title="Delete Passkey"
                                                                >
                                                                    <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="width: 16px; height: 16px;" xmlns="http://www.w3.org/2000/svg">
                                                                        <path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
                                                                    </svg>
                                                                </button>
                                                            </div>
                                                        }.into_any()
                                                    }
                                                }
                                            </div>
                                        </div>
                                    }
                                }
                            />
                        </div>
                    }.into_any()
                }
            }}

            {move || {
                rename_result.and_then(|sig| {
                    sig.get().map(|res| match res {
                        Ok(_) => view! {
                            <div style=success_box_style>
                                "Passkey renamed successfully."
                            </div>
                        }.into_any(),
                        Err(err) => view! {
                            <div style=error_box_style>
                                {err}
                            </div>
                        }.into_any(),
                    })
                })
            }}
            {move || {
                delete_result.and_then(|sig| {
                    sig.get().map(|res| match res {
                        Ok(_) => view! {
                            <div style=success_box_style>
                                "Passkey deleted successfully."
                            </div>
                        }.into_any(),
                        Err(err) => view! {
                            <div style=error_box_style>
                                {err}
                            </div>
                        }.into_any(),
                    })
                })
            }}
        </div>
    }
}
