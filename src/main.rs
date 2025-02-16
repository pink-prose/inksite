#[cfg(feature = "ssr")]
mod app_state;
mod components;
#[cfg(feature = "ssr")]
mod key;
#[cfg(feature = "ssr")]
mod mail;

#[cfg(feature = "ssr")]
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use crate::app_state::AppState;
    use crate::components::app::*;

    use actix_files::Files;
    use actix_web::*;
    use fred::prelude::ClientLike;
    use leptos::config::get_configuration;
    use leptos::prelude::*;
    use leptos_actix::{LeptosRoutes, generate_route_list_with_exclusions};
    use leptos_meta::MetaTags;
    use lettre::{AsyncSmtpTransport, Tokio1Executor};

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let conf = get_configuration(None).unwrap();
    let addr = conf.leptos_options.site_addr;

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL should be set");
    let db_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("database should open");

    sqlx::migrate!()
        .run(&db_pool)
        .await
        .expect("migrations should succeed");

    let valkey_url = std::env::var("VALKEY_URL").expect("VALKEY_URL should be set");
    let valkey_config = fred::prelude::Config::from_url(&valkey_url)
        .expect("should be able to construct Valkey config");
    let valkey_pool = fred::prelude::Pool::new(valkey_config, None, None, None, 5)
        .expect("should be able to create Valkey pool");
    valkey_pool
        .init()
        .await
        .expect("should be able to initialize Valkey pool");

    let smtp_url = std::env::var("SMTP_URL").expect("SMTP_URL should be set");
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::from_url(&smtp_url)
        .expect("should be able to initialize mailer")
        .build();

    let app_state = AppState {
        db_pool,
        valkey_pool,
        mailer,
    };

    HttpServer::new(move || {
        // Generate the list of routes in your Leptos App
        let routes = dbg!(generate_route_list_with_exclusions(
            App, None,
            // Some(vec!["/auth/email".to_string()])
        ));
        let leptos_options = &conf.leptos_options;
        let site_root = leptos_options.site_root.clone().to_string();
        let app_state = app_state.clone();

        App::new()
            // serve JS/WASM/CSS from `pkg`
            .service(Files::new("/pkg", format!("{site_root}/pkg")))
            // serve other assets from the `assets` directory
            .service(Files::new("/assets", &site_root))
            // serve the favicon from /favicon.ico
            .service(favicon)
            .leptos_routes_with_context(
                routes,
                move || {
                    let app_state = app_state.clone();
                    provide_context(app_state);
                },
                {
                    let leptos_options = leptos_options.clone();
                    move || {
                        view! {
                            <!DOCTYPE html>
                            <html lang="en">
                                <head>
                                    <meta charset="utf-8" />
                                    <meta
                                        name="viewport"
                                        content="width=device-width, initial-scale=1"
                                    />
                                    <AutoReload options=leptos_options.clone() />
                                    <HydrationScripts options=leptos_options.clone() />
                                    <MetaTags />
                                </head>
                                <body>
                                    <App />
                                </body>
                            </html>
                        }
                    }
                },
            )
            .app_data(web::Data::new(leptos_options.to_owned()))
            .wrap(middleware::Compress::default())
            .wrap(middleware::Logger::default())
    })
    .bind(&addr)?
    .run()
    .await
}

#[cfg(feature = "ssr")]
#[actix_web::get("favicon.ico")]
async fn favicon(
    leptos_options: actix_web::web::Data<leptos::config::LeptosOptions>,
) -> actix_web::Result<actix_files::NamedFile> {
    let leptos_options = leptos_options.into_inner();
    let site_root = &leptos_options.site_root;
    Ok(actix_files::NamedFile::open(format!(
        "{site_root}/favicon.ico"
    ))?)
}

#[cfg(not(any(feature = "ssr", feature = "csr")))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for pure client-side testing
    // see lib.rs for hydration function instead
    // see optional feature `csr` instead
}

#[cfg(all(not(feature = "ssr"), feature = "csr"))]
pub fn main() {
    // a client-side main function is required for using `trunk serve`
    // prefer using `cargo leptos serve` instead
    // to run: `trunk serve --open --features csr`
    use crate::components::app::*;

    console_error_panic_hook::set_once();

    leptos::mount_to_body(App);
}
