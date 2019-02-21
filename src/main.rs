#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate serde_derive;

use std::fs;
use std::path::PathBuf;
use std::cmp::Ordering;

use pest::Parser;
use structopt::{StructOpt};
use version_compare::{Version};

#[derive(Parser)]
#[grammar = "reqs.pest"]
struct ReqsParser;

#[derive(StructOpt, Debug)]
#[structopt(name = "pythv")]
struct Opts {
    /// Python requirements file to process
    #[structopt(name = "FILE", parse(from_os_str))]
    pub file: PathBuf
}

struct Requirement<'a> {
    pub name: String,
    pub version: Version<'a>,
}

struct Vulnerability<'a> {
    pub name: String,
    pub id: &'a str,
    pub version_data: &'a [VersionData]
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
struct CVEDataMeta {
    ID: String
}

#[derive(Serialize, Deserialize, Debug)]
struct DescriptionData {
    value: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Description {
    description_data: Vec<DescriptionData>
}

#[derive(Serialize, Deserialize, Debug)]
struct VersionData {
    version_value: String,
    version_affected: String
}

#[derive(Serialize, Deserialize, Debug)]
struct ParsedVersion {
    version_data: Vec<VersionData>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProductData {
    product_name: String,
    version: ParsedVersion,
}

#[derive(Serialize, Deserialize, Debug)]
struct Product {
    product_data: Vec<ProductData>,
}

#[derive(Serialize, Deserialize, Debug)]
struct VendorData {
    vendor_name: String,
    product: Product,
}

#[derive(Serialize, Deserialize, Debug)]
struct Vendor {
    vendor_data: Vec<VendorData>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Affects {
    vendor: Vendor,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
struct ImpactMetrics {
    severity: String,
    exploitabilityScore: f32,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
struct Impact {
    baseMetricV2: Option<ImpactMetrics>,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
struct CVE {
    CVE_data_meta: CVEDataMeta,
    affects: Affects,
    description: Description,
}

#[derive(Serialize, Deserialize, Debug)]
struct CVEItem {
    cve: CVE,
    impact: Impact,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
struct CVEData {
    CVE_Items: Vec<CVEItem>,
}

fn main() {
    let opt = Opts::from_args();
    let contents = fs::read_to_string(opt.file).unwrap();

    let reqs = ReqsParser::parse(Rule::req_list, &contents).unwrap();
    let mut requirements = Vec::new();
    for req_list in reqs {
        for pair in req_list.into_inner() {
            let vec: Vec<_> = pair.into_inner().flatten().collect();
            requirements.push(Requirement{
                name: vec[0].as_str().to_string().to_lowercase(),
                version: Version::from(vec[1].as_str()).expect("Failed to parse req from requirements.txt")
            });
        }
    }
    requirements.sort_by(|a, b| a.name.cmp(&b.name));

    let mut cve_data = Vec::new();
    for year in 2002..=2019 {
        let body = fs::read_to_string(format!("cve-data/nvdcve-1.0-{}.json", year)).unwrap();
        println!("Loaded CVE data from {}", year);
        let data: CVEData = serde_json::from_str(&body).unwrap();
        cve_data.extend(data.CVE_Items);
    }

    let mut vulnerability_data = Vec::new();
    for cve_item in &cve_data {
        for vendor_data in &cve_item.cve.affects.vendor.vendor_data {
            for product_data in &vendor_data.product.product_data {
                vulnerability_data.push(Vulnerability {
                    name: product_data.product_name.to_lowercase(),
                    id: &cve_item.cve.CVE_data_meta.ID,
                    version_data: &product_data.version.version_data
                });
            }
        }
    }
    vulnerability_data.sort_by(|a, b| a.name.cmp(&b.name));

    let mut vulernabilities = Vec::new();
    let mut req_index = 0;
    let mut vul_index = 0;
    while req_index < requirements.len() && vul_index < vulnerability_data.len() {
        let req = &requirements[req_index];
        let vulnerability = &vulnerability_data[vul_index];

        match req.name.cmp(&vulnerability.name) {
            Ordering::Greater => {
                vul_index += 1;
            },
            Ordering::Less => {
                req_index += 1;
            },
            Ordering::Equal => {
                let flag = vulnerability.version_data.iter().fold(false, |acc, version_data| {
                    if version_data.version_value == "*" {
                        return true;
                    }

                    let product_version = Version::from(&version_data.version_value)
                        .expect("Failed to parse version from CVE");

                    acc || match version_data.version_affected.as_ref() {
                        "=" => {
                            req.version == product_version
                        },
                        ">=" => {
                            req.version >= product_version
                        },
                        "<=" => {
                            req.version <= product_version
                        },
                        _ => unreachable!()
                    }
                });

                if flag {
                    vulernabilities.push((&req.name, vulnerability.id));
                }

                vul_index += 1;
            }
        }
    }

    vulernabilities.iter().for_each(|vul| {
        println!("{} {}", vul.0, vul.1);
    });
}
