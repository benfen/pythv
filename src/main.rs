#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate serde_derive;

use std::fs;
use std::path::PathBuf;

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

fn check_cve_item(item: &CVEItem, product: &Requirement) -> bool {
    let vendor_data_list = &item.cve.affects.vendor.vendor_data;

    for vendor_data in vendor_data_list {
        for product_data in &vendor_data.product.product_data {
            let product_name = &product_data.product_name;
            // println!("{} {}", product_name.to_lowercase(), product.to_lowercase());
            if product_name.to_lowercase() == product.name {
                    println!("{:?}\n", product_data);
                return product_data.version.version_data.iter().fold(false, |acc, version_data| {
                    if version_data.version_value == "*" {
                        return true;
                    }

                    let product_version = Version::from(&version_data.version_value)
                        .expect("Failed to parse version from CVE");

                    acc || match version_data.version_affected.as_ref() {
                        "=" => {
                            product.version == product_version
                        },
                        ">=" => {
                            product.version >= product_version
                        },
                        "<=" => {
                            product.version <= product_version
                        },
                        _ => unreachable!()
                    }
                });
            }
        }
    }

    false
}

fn scan_deps<'a, 'b>(reqs: &'a[Requirement], cve_years: &'b[CVEData]) -> Vec<(&'a Requirement<'a>, String)> {
    let mut findings = Vec::new();

    for req in reqs {
        for cve_year in cve_years {
            for cve_item in &cve_year.CVE_Items {
                if check_cve_item(&cve_item, &req) {
                    findings.push((req.clone(), cve_item.cve.CVE_data_meta.ID.clone()));
                }
            }
        }
    }

    findings
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

    let mut cve_data = Vec::new();
    for year in 2002..=2019 {
        let body = fs::read_to_string(format!("cve-data/nvdcve-1.0-{}.json", year)).unwrap();
        println!("Loaded CVE data from {}", year);
        let data: CVEData = serde_json::from_str(&body).unwrap();
        cve_data.push(data);
    }

    scan_deps(&requirements, &cve_data).iter().for_each(|finding| {
        println!("{}: {}", finding.0.name, finding.1);
    });
}
