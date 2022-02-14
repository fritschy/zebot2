use std::process::Command;

fn get_git_info(cmd: &[&str]) -> Option<String> {
    let output = Command::new("git").args(cmd).output().ok()?;
    let info = String::from_utf8(output.stdout).ok()?;
    Some(info)
}

fn main() {
    println!("cargo:rerun-if-changed=.git/index");
    if let Some(commit) = get_git_info(&["rev-parse", "--short", "HEAD"]) {
        if let Some(branch) = get_git_info(&["rev-parse", "--abbrev-ref", "HEAD"]) {
            println!("cargo:rustc-env=GIT_REV_INFO=r{}/{}", commit, branch);
        } else {
            println!("cargo:rustc-env=GIT_REV_INFO=r{}", commit);
        }
    } else {
        println!("cargo:rustc-env=GIT_REV_INFO=0");
    }
}
