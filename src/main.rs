#[macro_use]
extern crate pest_derive;
#[macro_use]
extern crate serde_derive;

use std::fs;
use std::path::PathBuf;

use pest::Parser;
use structopt::{StructOpt};

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

#[derive(Debug, Clone)]
struct Requirement {
    pub name: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug)]
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
struct Version {
    version_data: Vec<VersionData>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProductData {
    product_name: String,
    version: Version,
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
struct ImpactMetrics {
    severity: String,
    exploitabilityScore: f32,
}

#[derive(Serialize, Deserialize, Debug)]
struct Impact {
    baseMetricV2: Option<ImpactMetrics>,
}

#[derive(Serialize, Deserialize, Debug)]
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
struct CVEData {
    CVE_Items: Vec<CVEItem>,
}

fn check_cve_item(item: &CVEItem, product: &str) -> bool {
    let vendor_data_list = &item.cve.affects.vendor.vendor_data;

    for vendor_data in vendor_data_list {
        for product_data in &vendor_data.product.product_data {
            let product_name = &product_data.product_name;
            if product_name == product {
                return true;
            }
        }
    }

    false
}

fn scan_deps(reqs: &[Requirement], cve_years: &[CVEData]) -> Vec<(Requirement, String)> {
    let mut findings = Vec::new();

    for req in reqs {
        for cve_year in cve_years {
            for cve_item in &cve_year.CVE_Items {
                if check_cve_item(&cve_item, &req.name) {
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
            requirements.push(Requirement{ name: vec[0].as_str().to_string(), version: vec[1].as_str().to_string()});
        }
    }

    let mut cve_data = Vec::new();
    for year in 2002..=2019 {
        let body = fs::read_to_string(format!("cve-data/nvdcve-1.0-{}.json", year)).unwrap();
        println!("Loaded CVE data from {}", year);
        let data: CVEData = serde_json::from_str(&body).unwrap();
        cve_data.push(data);
    }

    println!("{:?}", scan_deps(&requirements, &cve_data));
}
