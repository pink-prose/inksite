use leptos::prelude::*;

/// Fetch the HTTP-only cookie.
#[server]
async fn get_registration_code() -> Result<Option<String>, ServerFnError> {
    use actix_web::HttpRequest;
    use leptos_actix::extract;

    let req: HttpRequest = extract().await?;
    leptos::logging::log!("Precode: {:#?}", req.cookie("reg_code"));
    let code = req.cookie("reg_code").map(|c| c.value().to_string());
    leptos::logging::log!("Code: {code:#?}");
    Ok(code)
}

// TODO - Delete the manual cookie fetching. Instead set a localstorage property for how long the
// cookie lasts and use that to solely determine whether they have a real email auth code.

#[component]
pub fn Register() -> impl IntoView {
    view! {
        <fieldset class="px-2 pt-1 pb-2 border-2 border-slate-500">
            <legend class="m-2 text-2xl font-bold">Register</legend>
            <Await future=get_registration_code() let:registration_code>
                {format!("The code is {:#?}", registration_code)}
            </Await>
        </fieldset>
    }
}
