#![deny(unsafe_code)]
use chrono::{TimeZone, Utc};
use futures::future::join_all;
use http::Extensions;
use reqwest::Client;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use tokio::sync::Semaphore;
use x509_parser::prelude::*;

struct CitrixNetscalerVersion {
    pub rdx_en_date: String,
    pub version: String,
}

#[derive(Debug)]
struct NetscalerHost {
    pub host_ip: String,
    pub version_date: Option<String>,
    pub version: Option<String>,
    pub host_name: Option<String>,
}

// From the source material, convert the timestamps by replacing spaces with a T
static SOURCE: &str = include_str!("versions.csv");
const CONCURRENCY_LIMIT: usize = 256;

fn parse_source() -> Vec<CitrixNetscalerVersion> {
    SOURCE
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() == 4 {
                Some(CitrixNetscalerVersion {
                    rdx_en_date: parts[0].to_string(),
                    version: parts[3].to_string(),
                })
            } else {
                None
            }
        })
        .collect()
}

// https://doc.rust-lang.org/stable/rust-by-example/std_misc/file/read_lines.html
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn extract_subject(ext: &Extensions) -> Option<String> {
    if let Some(val) = ext.get::<reqwest::tls::TlsInfo>()
        && let Some(peer_cert_der) = val.peer_certificate()
    {
        match X509Certificate::from_der(peer_cert_der) {
            Ok((rem, cert)) => {
                if cert.version() != X509Version::V3 || !rem.is_empty() {
                    return None;
                }
                let subject = cert
                    .tbs_certificate
                    .subject()
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok());
                return subject.map(std::string::ToString::to_string);
            }
            _ => Option::<String>::None,
        };
    }
    None
}

async fn process_url(
    client: &reqwest::Client,
    host_ip: &str,
) -> Result<NetscalerHost, reqwest::Error> {
    let url = format!("https://{}/vpn/js/rdx/core/lang/rdx_en.json.gz", host_ip);
    let res = client.get(url).send().await?;
    let ext = res.extensions();
    let subject = extract_subject(ext);
    let body = res.bytes().await?;

    // If the body is less than 8 bytes, the below slices will crash. The larger size adds to the sanity check
    if body.len() < 16 {
        return Ok(NetscalerHost {
            host_ip: host_ip.to_string(),
            version: None,
            version_date: None,
            host_name: subject,
        });
    }
    // Verify gzip header - this ensures we have a valid gzip file at the test URL
    if *body.slice(0..4) != *b"\x1f\x8b\x08\x08" {
        return Ok(NetscalerHost {
            host_ip: host_ip.to_string(),
            version: None,
            version_date: Some("Invalid gzip header".to_string()),
            host_name: subject,
        });
    }
    let mut version_bytes = [0u8; 4];
    version_bytes.copy_from_slice(&body[4..8]);
    let version_u32 = u32::from_le_bytes(version_bytes);
    let dt = Utc.timestamp_opt(i64::from(version_u32), 0).single();
    let utc_string = dt.map(|d| d.to_rfc3339());

    Ok(NetscalerHost {
        host_ip: host_ip.to_string(),
        version: None,
        version_date: utc_string,
        host_name: subject,
    })
}

fn insert_netscaler_to_db(host: &NetscalerHost) {
    println!(
        "{},{},{},{}",
        host.host_ip,
        host.version.as_deref().unwrap_or("Unknown"),
        host.version_date.as_deref().unwrap_or("Unknown"),
        host.host_name.as_deref().unwrap_or("Unknown")
    );
}

#[tokio::main]
async fn main() {
    // Create vector of CitrixNetscalerVersion from SOURCE
    let versions: Vec<CitrixNetscalerVersion> = parse_source();

    // Regardless of usual warnings, disable SSL verification is not dangerous and is needed to scan IP addresses with unknown names on certs
    let client = Client::builder()
        .tls_info(true)
        .danger_accept_invalid_certs(true)
        .build()
        .expect("should be able to build reqwest client");

    let hosts = match read_lines("./hosts.txt") {
        Ok(lines) => lines,
        Err(e) => {
            eprintln!("Error reading hosts.txt: {}", e);
            return;
        }
    };

    let semaphore = std::sync::Arc::new(Semaphore::new(CONCURRENCY_LIMIT));

    // Spawn all requests concurrently, but limit concurrency
    let futures = hosts.map_while(Result::ok).map(|host_ip| {
        let client = &client;
        let versions = &versions;
        let semaphore = semaphore.clone();

        async move {
            // Acquire a permit before proceeding
            let _permit = semaphore.acquire_owned().await.unwrap();

            let valid_ip = host_ip.parse::<std::net::IpAddr>().is_ok();
            if !valid_ip {
                let scanned_host: NetscalerHost = NetscalerHost {
                    host_ip: host_ip.to_string(),
                    version: Some("Unknown".to_string()),
                    version_date: None,
                    host_name: Some("Invalid IP address".to_string()),
                };
                insert_netscaler_to_db(&scanned_host);
                //dbg!(scanned_host);
                return;
            }

            match process_url(client, &host_ip).await {
                Ok(mut scanned_host) => {
                    let default_version = "Unknown".to_string();
                    let version_date = scanned_host
                        .version_date
                        .as_ref()
                        .unwrap_or(&default_version);
                    let version = versions
                        .iter()
                        .find(|v| v.rdx_en_date == *version_date)
                        .map_or("Unknown", |v| &v.version);
                    scanned_host.version = Some(version.to_string());
                    // Common failure here is duplicates in the source hosts file. Just log and continue
                    insert_netscaler_to_db(&scanned_host);
                    //dbg!(scanned_host);
                }
                Err(e) => {
                    let scanned_host: NetscalerHost = NetscalerHost {
                        host_ip: host_ip.to_string(),
                        version: Some("Unknown".to_string()),
                        version_date: None,
                        host_name: Some(e.to_string()),
                    };
                    let _ = insert_netscaler_to_db(&scanned_host);
                    //dbg!(scanned_host);
                }
            }
            // _permit is dropped here, releasing the slot
        }
    });

    join_all(futures).await;
}
