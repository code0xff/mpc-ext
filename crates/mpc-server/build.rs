// `sqlx::migrate!` embeds the migrations at compile time; without this, adding a migration file
// does not trigger a rebuild and the server silently runs the old schema.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
