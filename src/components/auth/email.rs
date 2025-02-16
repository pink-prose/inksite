use crate::components::ui::*;

use leptos::prelude::*;
use leptos_router::components::*;
use leptos_router::hooks::use_params_map;
use leptos_router::{MatchNestedRoutes, path};
use serde::{Deserialize, Serialize};

#[cfg(feature = "ssr")]
use std::collections::HashMap;

#[cfg(feature = "ssr")]
use crate::app_state::*;
#[cfg(feature = "ssr")]
use crate::key;

#[cfg(feature = "ssr")]
use fred::prelude::{HashesInterface, KeysInterface, TransactionInterface};
#[cfg(feature = "ssr")]
use rand::{
    distributions::{Alphanumeric, DistString},
    thread_rng,
};

const LOGIN_SESSION_EXPIRATION_MIN: i64 = 20;

#[cfg(feature = "ssr")]
const CHALLENGE_LENGTH: usize = 32;
const RESPONSE_LENGTH: usize = 8;

/// Route definitions for email auth stages.
#[component(transparent)]
pub fn EmailRoutes() -> impl MatchNestedRoutes + Clone {
    view! {
        <ParentRoute path=path!("email") view=EmailWrapper>
            <Route path=path!("") view=Start />
            <Route path=path!("challenge") view=Challenge />
            <Route path=path!("response") view=Challenge />
        </ParentRoute>
    }
    .into_inner()
}

/// Email authentication first stage, where a challenge is generated and
/// returned, while the correct response is sent via email.
///
/// See https://en.wikipedia.org/wiki/Challenge%E2%80%93response_authentication
#[server]
async fn get_email_login_challenge(email: String) -> Result<String, ServerFnError> {
    use crate::mail;

    use lettre::AsyncTransport;

    leptos::logging::log!("get_email_login_challenge exercised");

    let address = match email.parse::<lettre::address::Address>() {
        Ok(email) => email,
        Err(_) => return Err(ServerFnError::new("Bad email")),
    };

    let app_state = use_app_state()?;
    let challenge = Alphanumeric.sample_string(&mut thread_rng(), CHALLENGE_LENGTH);
    let response = Alphanumeric.sample_string(&mut thread_rng(), RESPONSE_LENGTH);

    let message = mail::login_code(address, &response, LOGIN_SESSION_EXPIRATION_MIN)
        .or_else(|err| Err(ServerFnError::new(format!("Couldn't send mail: {err}"))))?;
    app_state
        .mailer
        .send(message)
        .await
        .or_else(|err| Err(ServerFnError::new(format!("Couldn't send mail: {err}"))))?;

    let tx = app_state.valkey_pool.multi();
    let key = key::email_auth_code(&challenge);
    let _: () = tx
        .hset(
            &key,
            HashMap::from([("email", email), ("response", response)]),
        )
        .await?;
    let _: () = tx
        .expire(&key, LOGIN_SESSION_EXPIRATION_MIN * 60, None)
        .await?;
    let _: () = tx.exec(false).await?;
    Ok(challenge)
}

/// Email authentication second stage, where the challenge is answered.
#[derive(Clone, Deserialize, Serialize)]
pub enum EmailAnswerResponse {
    LoggedIn,
    NeedToRegister,
    BadCode,
}

/// Note that, for security reasons, we can't tell the user which exactly of
/// (email, challenge, response) was wrong.
#[server]
async fn answer_email_login_challenge(
    email: String,
    challenge: String,
    response: String,
) -> Result<EmailAnswerResponse, ServerFnError> {
    use EmailAnswerResponse as EAR;
    use uuid::Uuid;

    if email.len() <= 0
        || challenge.len() != CHALLENGE_LENGTH
        || response.len() != RESPONSE_LENGTH
        || !challenge.chars().all(char::is_alphanumeric)
        || !response.chars().all(char::is_alphanumeric)
    {
        leptos::logging::debug_warn!("Rejecting invalid login challenge inputs");
        // Note that the actual form should never send these inputs.
        return Ok(EAR::BadCode);
    }

    let app_state = use_app_state()?;
    let key = key::email_auth_code(&challenge);
    let correct_data: HashMap<String, String> = match app_state
        .valkey_pool
        .hgetall::<Option<HashMap<String, String>>, _>(&key)
        .await?
    {
        Some(value) => value,
        None => return Ok(EAR::BadCode), // No matching challenge = wrong login.
    };

    let correct_email = match correct_data.get("email") {
        Some(value) => value,
        None => return Ok(EAR::BadCode), // No email = wrong login.
    };
    let correct_response = match correct_data.get("response") {
        Some(value) => value,
        None => return Ok(EAR::BadCode), // No response = wrong login.
    };
    if email != *correct_email || response != *correct_response {
        return Ok(EAR::BadCode); // Wrong email or response = wrong login.
    }

    // Response accepted; clean it up as it's a one-time code.
    tokio::spawn(async move {
        if let Err(err) = app_state.valkey_pool.del::<(), _>(&key).await {
            leptos::logging::warn!("Error deleting key {key} ignored: {err}");
        }
    });

    use actix_web::cookie::time::{Duration, OffsetDateTime};
    use actix_web::cookie::{Cookie, SameSite};
    use actix_web::http::header::{HeaderValue, SET_COOKIE};

    match sqlx::query_as::<_, (Uuid, bool, Option<String>, Option<String>)>(
        r#"
        select
          account.id,
          ask_for_profile_on_login,
          profile.username,
          profile.display_name
        from
          account
          left join profile on account.default_profile = profile.id
        where
          email = $1
          or $1 = any(secondary_email)
        limit 1
        "#,
    )
    .bind(&email)
    .fetch_optional(&app_state.db_pool)
    .await
    .or_else(|err| {
        Err(ServerFnError::new(format!(
            "Couldn't get account from DB: {err}"
        )))
    })? {
        Some((_account_id, _ask_for_profile_on_login, _username, _display_name)) => {
            leptos::logging::log!("You do have an account");
            Ok(EAR::LoggedIn)
        }
        None => {
            leptos::logging::log!("You don't have an account");
            let response_options = use_context::<leptos_actix::ResponseOptions>()
                .ok_or_else(|| ServerFnError::new("No response options object"))?;
            let registration_code = Alphanumeric.sample_string(&mut thread_rng(), 32);
            let mut registration_cookie = Cookie::new("reg_code", registration_code);
            registration_cookie.set_expires(OffsetDateTime::now_utc() + Duration::hours(1));
            registration_cookie.set_path("/"); // Must be / as server functions will be under /api.
            registration_cookie.set_same_site(SameSite::Lax);

            response_options.append_header(
                SET_COOKIE,
                HeaderValue::from_str(&registration_cookie.to_string())
                    .expect("alphanumeric string should always encode successfully"),
            );

            leptos_actix::redirect("/auth/register");
            Ok(EAR::NeedToRegister)
        }
    }
}

#[component]
pub fn EmailWrapper() -> impl IntoView {
    view! {
        <p>"Hello. You actually changed something."</p>
        <fieldset class="px-2 pt-1 pb-2 mb-2 border-2 border-slate-500">
            <legend class="mx-2 text-2xl font-bold">Email challenge</legend>
            <p>Receive and input a login code sent to the given email address.</p>
            <Outlet />
        </fieldset>
    }
}

#[component]
pub fn Start() -> impl IntoView {
    view! {
        <p>"Hello. You are inside Start."</p>
        <Form action="challenge" method="GET">
            <div class="flex gap-2">
                <label for="email">Email:</label>
                <input
                    type="email"
                    name="email"
                    placeholder="email"
                    class="px-1 h-full bg-gray-200 border border-gray-500 invalid:border-red-500"
                    required
                />
                <input
                    type="submit"
                    value="Email me"
                    class="px-2 h-full bg-green-200 hover:bg-green-300"
                />
            </div>
        </Form>
    }
}

#[component]
pub fn Challenge() -> impl IntoView {
    return view! { <p>"Short circuit challenge"</p> }.into_any();

    let params = use_params_map();
    leptos::logging::log!("Exercised Challenge params: {params:#?}");
    let email = match params.read().get("email") {
        Some(email) => email,
        None => return view! { <Redirect path=".." /> }.into_any(),
    };
    leptos::logging::log!("Exercised Challenge");

    view! {
        <p>"Hello. You are inside Challenge."</p>
        <Await future=get_email_login_challenge(email.clone()) let:challenge>
            {
                let challenge = challenge.clone();
                view! {
                    <Form action="response" method="GET">
                        <div class="flex gap-2">
                            <label for="email">Email:</label>
                            <input
                                type="email"
                                name="email"
                                placeholder="email"
                                class="px-1 h-full bg-gray-200 border border-gray-500 invalid:border-red-500"
                                required
                                readonly
                                value=email.clone()
                            />
                            <input
                                type="submit"
                                value="Email me"
                                class="px-2 h-full bg-green-200 hover:bg-green-300"
                                disabled
                            />
                        </div>

                        <p>
                            "An email has been sent to " {email.clone()}
                            " with a login code; please enter it here within "
                            {LOGIN_SESSION_EXPIRATION_MIN} " minutes".
                        </p>

                        <div class="flex gap-2">
                            // <input
                            // type="hidden"
                            // name="challenge"
                            // placeholder="challenge"
                            // value=challenge.clone().unwrap_or_default()
                            // />
                            <p>{format!("The challenge is {challenge:#?}")}</p>
                            <label for="response">Login code:</label>
                            <input
                                type="text"
                                name="response"
                                placeholder="response"
                                class="px-1 h-full bg-gray-200 border border-gray-500 invalid:border-red-500"
                                minlength=RESPONSE_LENGTH
                                maxlength=RESPONSE_LENGTH
                                pattern="^[A-Za-z0-9]*$"
                                title=format!(
                                    "exactly {RESPONSE_LENGTH} uppercase, lowercase, or numeric characters",
                                )
                                required
                                autocomplete="off"
                                value=""
                            />
                            <input
                                type="submit"
                                value="Submit code"
                                class="px-2 h-full bg-green-200 hover:bg-green-300"
                            />
                        </div>
                    </Form>
                }
            }
        </Await>
    }
    .into_any()
}

#[component]
pub fn EmailAuth() -> impl IntoView {
    let get_email_login_challenge = ServerAction::<GetEmailLoginChallenge>::new();
    let answer_email_login_challenge = ServerAction::<AnswerEmailLoginChallenge>::new();

    let email = RwSignal::new("".to_string());
    let challenge = RwSignal::new("".to_string());
    // The last email address that was submitted (not the one currently entered
    // into the form).
    let last_email = RwSignal::new("".to_string());

    let _save_last_email = Effect::new(move || {
        // input is cleared as soon as the server action resolves, so we must
        // save this so the UI doesn't update then.
        if let Some(server_last_email) = get_email_login_challenge.input().get() {
            last_email.set(server_last_email.email);
        }
    });

    let code_input_elem = NodeRef::<leptos::html::Input>::new();

    // Handler after receiving the challenge from the server.
    let _receive_challenge = Effect::new(move || {
        if let Some(Ok(server_challenge)) = get_email_login_challenge.value().get() {
            challenge.set(server_challenge);
            if let Some(node) = code_input_elem.get() {
                if let Err(err) = node.focus() {
                    leptos::logging::warn!("Error focusing code input: {err:?}");
                }
            } else {
                leptos::logging::warn!("Wanted to focus code input, but it wasn't mounted");
            }
        }
    });

    let _receive_response = Effect::new(move || {
        match answer_email_login_challenge.value().get() {
            Some(Ok(EmailAnswerResponse::NeedToRegister)) => {
                leptos::logging::log!("effect got to run before redirect");
                // let (_, set_registration_ready, _) = leptos_use::use_local_storage<bool, FromToStringCodec>("reg_ready");
                // set_registration_ready();
            }
            _ => (), // All other cases do nothing.
        }
    });

    view! {
        <fieldset class="px-2 pt-1 pb-2 mb-2 border-2 border-slate-500">
            <legend class="mx-2 text-2xl font-bold">Email challenge</legend>

            <p>Receive and input a login code sent to the given email address.</p>

            <ActionForm action=get_email_login_challenge>
                <div class="flex gap-2">
                    <label for="email">Email:</label>
                    <input
                        type="email"
                        name="email"
                        placeholder="email"
                        class="px-1 h-full bg-gray-200 border border-gray-500 invalid:border-red-500"
                        required
                        bind:value=email
                    />
                    <input
                        type="submit"
                        value="Email me"
                        class="px-2 h-full bg-green-200 hover:bg-green-300"
                    />
                    <Show when=move || { *get_email_login_challenge.pending().read() }>
                        <span class="self-center">
                            <Spinner />
                        </span>
                    </Show>
                </div>
            </ActionForm>

            <Show
                when=move || {
                    get_email_login_challenge.value().with(|val| matches!(val, Some(Ok(_))))
                }
                fallback=move || {
                    view! {
                        {move || {
                            match get_email_login_challenge.value().get() {
                                Some(Err(err)) => {
                                    view! { <ShowServerFnError error=err /> }.into_any()
                                }
                                _ => view! {}.into_any(),
                            }
                        }}
                    }
                }
            >
                <p>
                    "An email has been sent to " {last_email}
                    " with a login code; please enter it here within "
                    {LOGIN_SESSION_EXPIRATION_MIN} " minutes".
                </p>

                <ActionForm action=answer_email_login_challenge>
                    <div class="flex gap-2">
                        <input type="hidden" name="email" placeholder="email" bind:value=email />
                        <input
                            type="hidden"
                            name="challenge"
                            placeholder="challenge"
                            bind:value=challenge
                        />
                        <label for="response">Login code:</label>
                        <input
                            type="text"
                            name="response"
                            placeholder="response"
                            class="px-1 h-full bg-gray-200 border border-gray-500 invalid:border-red-500"
                            minlength=RESPONSE_LENGTH
                            maxlength=RESPONSE_LENGTH
                            pattern="^[A-Za-z0-9]*$"
                            title=format!(
                                "exactly {RESPONSE_LENGTH} uppercase, lowercase, or numeric characters",
                            )
                            required
                            autocomplete="off"
                            value=""
                            node_ref=code_input_elem
                        />
                        <input
                            type="submit"
                            value="Submit code"
                            class="px-2 h-full bg-green-200 hover:bg-green-300"
                        />
                        <Show when=move || { answer_email_login_challenge.pending().get() }>
                            <span class="self-center">
                                <Spinner />
                            </span>
                        </Show>
                    </div>
                </ActionForm>

                <Show
                    when=move || {
                        answer_email_login_challenge.value().with(|val| matches!(val, Some(Ok(_))))
                    }
                    fallback=move || {
                        view! {
                            {move || {
                                if let Some(Err(err)) = answer_email_login_challenge.value().get() {
                                    view! { <ShowServerFnError error=err /> }.into_any()
                                } else {
                                    view! {}.into_any()
                                }
                            }}
                        }
                    }
                >
                    {move || {
                        if let Some(Ok(response)) = answer_email_login_challenge.value().get() {
                            use EmailAnswerResponse as EAR;
                            match response {
                                EAR::LoggedIn => view! { "Login code accepted." }.into_any(),
                                EAR::NeedToRegister => {
                                    view! {
                                        "You don't have an account yet. If you would like to create one and are not redirected automatically, "
                                        <ANorm href="/auth/register">click here</ANorm>
                                        "."
                                    }
                                        .into_any()
                                }
                                EAR::BadCode => {
                                    view! { "Login code rejected. Try again." }.into_any()
                                }
                            }
                        } else {
                            view! { "" }.into_any()
                        }
                    }}
                </Show>
            </Show>

        </fieldset>
    }
}
