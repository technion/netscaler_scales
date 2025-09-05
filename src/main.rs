#![deny(unsafe_code)]
use chrono::{TimeZone, Utc};
use futures::future::join_all;
use reqwest::Client;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use x509_parser::prelude::*;

// We don't need most of these fields, but we use this so we can copy paste the source table
struct CitrixNetscalerVersion {
    pub rdx_en_date: String,
    pub version: String,
}

// From the source material, convert the timestamps by replacing spaces with a T
static SOURCE: &str = r#"2024-07-04T16:31:28+00:00,1720110688,,14.1-25.56
2024-07-04T16:49:33+00:00,1720111773,,13.1-37.190
2024-07-05T06:07:38+00:00,1720159658,,14.1-25.108
2024-07-08T18:53:11+00:00,1720464791,,13.0-92.31
2024-07-17T17:53:35+00:00,1721238815,,13.1-54.29
2024-08-13T11:43:40+00:00,1723549420,,13.1-37.199
2024-10-07T20:11:28+00:00,1728331888,,13.1-37.207
2024-10-07T20:55:33+00:00,1728334533,a7c411815373059b33b4d83bed6145a2,12.1-55.321
2024-10-11T10:23:04+00:00,1728642184,,14.1-29.72
2024-10-21T20:52:15+00:00,1729543935,0dd3f401dd33679f07e06961db10a298,12.1-55.321
2024-10-22T01:37:14+00:00,1729561034,,14.1-34.42
2024-10-24T13:43:49+00:00,1729777429,,13.1-55.34
2024-10-29T06:55:25+00:00,1730184925,,14.1-34.101
2024-11-07T16:17:10+00:00,1730996230,,13.1-56.18
2024-11-29T10:21:03+00:00,1732875663,,13.1-37.219
2024-12-16T17:20:08+00:00,1734369608,,14.1-38.53
2025-01-25T10:12:49+00:00,1737799969,,13.1-57.26
2025-02-11T01:19:25+00:00,1739236765,c624dcce8d3355d555021d2aac5f9715,12.1-55.325
2025-02-21T16:41:24+00:00,1740156084,,14.1-43.50
2025-03-06T13:19:10+00:00,1741267150,,14.1-34.105
2025-03-14T09:32:59+00:00,1741944779,,14.1-34.107
2025-04-01T08:43:29+00:00,1743497009,,13.1-37.232
2025-04-08T14:08:19+00:00,1744121299,,13.1-58.21
2025-04-09T07:52:44+00:00,1744185164,,14.1-43.109
2025-05-13T17:58:16+00:00,1747159096,,14.1-47.40
2025-05-20T07:48:42+00:00,1747727322,,14.1-47.43
2025-05-21T08:05:34+00:00,1747814734,,14.1-47.44
2025-06-07T13:53:15+00:00,1749304395,,14.1-47.46
2025-06-10T10:53:47+00:00,1749552827,,14.1-43.56
2025-06-10T14:02:25+00:00,1749564145,89929af92ff35a042d78e9010b7ec534,12.1-55.328
2025-06-10T16:26:42+00:00,1749572802,,13.1-37.235
2025-06-10T20:52:27+00:00,1749588747,,13.1-58.32
2025-06-17T04:21:23+00:00,1750134083,f069136a9297a52b6d86a5de987d9323,12.1-55.328
2025-06-18T13:04:11+00:00,1750251851,,13.1-59.19
2025-08-20T12:21:05+00:00,1755692465,765c645f7af4a1ef5c11d464fafc6244,12.1-55.330
2025-08-20T12:23:35+00:00,1755692615,,14.1-47.48
2025-08-20T12:35:34+00:00,1755693334,,13.1-37.241
2025-08-20T12:44:46+00:00,1755693886,,13.1-59.22
2025-08-26T02:22:30+00:00,1756174950,a53b1af56a97019171ec39665fedc54a,12.1-55.330"#;

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

async fn process_url(client: &reqwest::Client, url: &str) -> Result<String, reqwest::Error> {
    let res = client.get(url).send().await?;

    let ext = res.extensions();

    if let Some(val) = ext.get::<reqwest::tls::TlsInfo>()
    { 
        if let Some(peer_cert_der) = val.peer_certificate() {

            let cert = 
            match X509Certificate::from_der(peer_cert_der) {
                Ok((rem, cert)) => {
                    assert!(rem.is_empty());
                    assert_eq!(cert.version(), X509Version::V3);
                    Some(cert.tbs_certificate)
                },
                _ => {
                     None
                },
            };
            println!("Cert: {:?}", cert.ok_or("No Subject").unwrap().subject().iter_common_name().next().and_then(|cn| cn.as_str().ok()));

        }
    }

    let body = res.bytes().await?;
    println!("Body: {:?}", body.slice(0..8));
    let mut version_bytes = [0u8; 4];
    version_bytes.copy_from_slice(&body[4..8]);
    let version_u32 = u32::from_le_bytes(version_bytes);
    let dt = Utc.timestamp_opt(version_u32 as i64, 0).single().unwrap();
    let utc_string = dt.to_rfc3339();


    Ok(utc_string)
}

#[tokio::main]
async fn main() {
    // Create vector of CitrixNetscalerVersion from SOURCE
    let versions: Vec<CitrixNetscalerVersion> = parse_source();
    dbg!(
        "Parsed versions: {:?}",
        versions.iter().map(|v| &v.rdx_en_date).collect::<Vec<_>>()
    );

    let client = Client::builder()
        .tls_info(true)
        .build()
        .expect("should be able to build reqwest client");

    let hosts = match read_lines("./hosts.txt") {
        Ok(lines) => lines,
        Err(e) => {
            eprintln!("Error reading hosts.txt: {}", e);
            return;
        }
    };
 
    // Spawn all requests concurrently
    let futures = hosts.map_while(Result::ok).map(|line| {
        let client = &client;
        let url = format!("https://{}/vpn/js/rdx/core/lang/rdx_en.json.gz", line);
        let versions = &versions;
        async move {
            println!("{}", url);
            match process_url(client, &url).await {
                Ok(datestamp) => {
                    println!("Datestamp: {}", datestamp);
                    let version = versions
                        .iter()
                        .find(|v| v.rdx_en_date == datestamp)
                        .map_or("Unknown", |v| &v.version);
                    println!("{}", version);
                }
                Err(e) => {
                    eprintln!("Error processing {}: {}", url, e);
                }
            }
        }
    });

    join_all(futures).await;
}
