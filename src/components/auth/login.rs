/// Login/new registration views.
use leptos::prelude::*;
use leptos_router::components::A;

#[component]
fn LoginMethodEntry(
    endpoint: &'static str,
    text_label: &'static str,
    children: Children,
) -> impl IntoView {
    view! {
        <A href=endpoint>
            <div class="flex flex-col items-center">
                <button class="p-4 text-4xl font-bold bg-transparent border-4 hover:bg-gray-300">
                    {children()}
                </button>
                <p>{text_label}</p>
            </div>
        </A>
    }
}

/// Main login page.
#[component]
pub fn LoginMethods() -> impl IntoView {
    view! {
        <div class="flex flex-col gap-4">
            <fieldset class="px-2 pt-1 pb-2 border-2 border-slate-500">
                <legend class="m-2 text-2xl font-bold">Login or register</legend>
                <div class="flex flex-row gap-2">
                    <LoginMethodEntry endpoint="email" text_label="Email login code">
                        "📧"
                    </LoginMethodEntry>
                </div>
            </fieldset>
            <fieldset class="px-2 pt-1 pb-2 border-2 border-slate-500">
                <legend class="m-2 text-2xl font-bold">Login only</legend>
                <div class="flex flex-row gap-2">
                    <LoginMethodEntry endpoint="" text_label="?">
                        "?"
                    </LoginMethodEntry>
                    <LoginMethodEntry endpoint="" text_label="?">
                        "?"
                    </LoginMethodEntry>
                    <LoginMethodEntry endpoint="" text_label="?">
                        "?"
                    </LoginMethodEntry>
                </div>
            </fieldset>
        </div>
    }
}
