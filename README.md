# Inksite

## Getting started

To run a development environment, first create a file `.env` that sets some required environment variables.

```
POSTGRES_USER=postgres
POSTGRES_PASSWORD=my_db_password
POSTGRES_DB=ink
```

Then, run from the project root directory:

```shell
docker compose up --watch
```

If you make changes to a `Dockerfile` or the `docker-compose.yml` environment, you may have to pass `--build` and `--remove-orphans` to `docker compose` to rebuild the images.

### Receiving email

All emails sent in the dev environment, e.g. email login codes, are collected by a locally running [Mailpit](https://mailpit.axllent.org/) instance. Go to `localhost:8025` to view the emails sent.

### Test data

To wipe Postgres and Valkey data, simply run:

```shell
rm -rf docker/data
```

Or you can save the data to a different location for testing.

### Build output

By default, build outputs are persisted in `docker/site` and `docker/target` so incremental builds can be done even after the container is rebuilt. You can wipe this output simply by deleting these directories.

### Running commands

To attach to and run arbitrary commands in the running container (for example, to use the `sqlx` CLI):

```shell
docker exec -it inksite bash
```

To run `psql` to use the database directly (`sh -c` is needed to expand `$POSTGRES_USER`):

```shell
docker exec -it postgres sh -c 'psql -U $POSTGRES_USER -d $POSTGRES_DB'
```

Database migrations are incremental changes to the database schema over time, for use in development and when deploying new versions of the server. The `sqlx` CLI is included in the main application container, which also has the `DATABASE_URL` env var set already. So when you start `bash` in the main container, `sqlx` will just work. If you prefer, you can also run `sqlx` from your host system, passing in the correct value for `--database_url`. Consult `sqlx help` for more info.

To run `valkey-cli` to inspect and write the contents of Valkey:

```shell
docker exec -it valkey sh -c 'valkey-cli'
```

Also helpful is the `MONITOR` command, which prints out every command it receives:

```shell
docker exec -it valkey sh -c 'valkey-cli monitor'
```

### Memory overcommit

The option `vm.overcommit_memory` is necessary for Valkey to ensure persistence works ([1](https://redis.io/docs/latest/develop/get-started/faq/#background-saving-fails-with-a-fork-error-on-linux), [2](https://medium.com/@akhshyganesh/redis-enabling-memory-overcommit-is-a-crucial-configuration-68dbb77dae5f)). This is a property of the host OS and not the Valkey container. If unset, Valkey will print a warning when it starts. You can dismiss the warning by running

```shell
sudo sysctl vm.overcommit_memory=1
```

in the host before starting Valkey. To save this setting between reboots, add

```
vm.overcommit_memory = 1
```

to `/etc/sysctl.conf`.

## Troubleshooting

### Starting over

The command

```
docker compose up --watch --build
```

still doesn't necessarily redo cached steps. Try stopping all containers and running

```
docker system prune --all
```

if you really want to make sure everything is being recreated from scratch.

### `wasm-bindgen` version

You may see an error message like this when building the frontend after a `git pull`.

```
       it looks like the Rust project used to create this Wasm file was linked against
       version of wasm-bindgen that uses a different bindgen format than this binary:

         rust Wasm file schema version: 0.2.100
            this binary schema version: 0.2.99

       Currently the bindgen format is unstable enough that these two schema versions
       must exactly match. You can accomplish this by either updating this binary or
       the wasm-bindgen dependency in the Rust project.
```

All three of the following need to be in sync:

- `wasm-bindgen` specified in `Cargo.toml`
- `wasm-bindgen-cli` installed at the user/system level in Docker (matches `wasm-bindgen`)
- `cargo-leptos` installed at the user/system level in Docker (depends on same version of `wasm-bindgen`)

All three should be pinned to compatible versions in Docker. You may need to rebuild the main container to install newer versions of the packages.

```
docker compose --watch --build
```

### Styles not updating

In some circumstances, hot reloading will update the `class` attribute, but may not reload the stylesheet. Tailwind, when building, generates a stylesheet with only the utility classes that are actually used in the project. This is a problem if you use any new Tailwind classes that haven't been previously generated; the browser will not see the new CSS classes in its cached stylesheet. To fix this, hard refresh (`ctrl-shift-r`) your browser manually or disable caching.

Even if the daisyUI version is changed in `package.json`, daisyUI is only installed/updated on image creation. To really update to a new version, you can attach to the container after the updated `package.json` is copied over by Docker compose watch and run `npm install` again, or delete and recreate the image.

### Missing new files, compilation errors after `git pull`, etc.

If on a restart of `docker compose --watch`, `rustc` claims a newly-added file is missing, you get compilation errors after a `git pull`, or you otherwise get compilation errors that don't make sense, then your container's source code may be out of sync with the state of the host's. This can happen if files are updated while Docker compose is not running. If you suspect this happened, simply rebuild the container.

```
docker compose --watch --build
```

### Database migration failure

Database migrations can fail if changes were made to a migration file after it was run.

```
[2025-02-02T23:53:57Z INFO  sqlx::postgres::notice] relation "_sqlx_migrations" already exists, skipping

thread 'main' panicked at src/main.rs:39:10:
migrations should succeed: VersionMismatch(20250202003439)
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

You can revert the whole DB to a clean state with `sqlx database reset`, or try undoing the latest migration with `sqlx migrate revert` and redoing it with `sqlx migrate run`. Note that this may result in data loss (of your test data).

## Miscellaneous

### Avoiding wasm build errors

There are numerous dependencies that can and should only run on the server. `cargo-leptos` builds the server by enabling the `ssr` feature. When adding a server-only dependency, you also need to configure it to be optional and only built when the `ssr` feature is enabled in `Cargo.toml`. Otherwise, Cargo will build them targeting wasm, and you'll likely get a build error involving `mio`, OpenSSL, or similar. For example:

```toml
[dependencies]
# ...
fred = { version = "10.0.3", features = ["transactions", "enable-native-tls"], optional = true }
# ...

[features]
ssr = [
  # ...
  "dep:fred",
  # ...
]
```

Additionally, you'll need to specify that any code that uses the library is only to be built when the `ssr` feature is enabled.

```rust
#[cfg(feature = "ssr")]
mod app_state; // Entire module set to conditionally compile in SSR mode

#[cfg(feature = "ssr")]
struct MyStruct {
  // ...
}
```

The `server` module already is configured this way in `main.rs`.
