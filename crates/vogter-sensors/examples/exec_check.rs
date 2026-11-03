//! Debug helper: show what the exec rules see for a live PID.
//! `cargo run -p vogter-sensors --example exec_check -- <pid>`
fn main() {
    let pid: i32 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .expect("usage: exec_check <pid>");
    let e = vogter_sensors::process::exec_info(pid).expect("process not found");
    println!("{e:#?}");
}
