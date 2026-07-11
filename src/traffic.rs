use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct HarRoot {
    log: HarLog,
}

#[derive(Debug, Deserialize)]
struct HarLog {
    entries: Vec<HarEntry>,
}

#[derive(Debug, Deserialize)]
struct HarEntry {
    request: HarRequest,
    response: HarResponse,
}

#[derive(Debug, Deserialize)]
struct HarRequest {
    post_data: Option<HarPostData>,
}

#[derive(Debug, Deserialize)]
struct HarPostData {
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HarResponse {
    status: u16,
}

#[derive(Debug, Serialize)]
pub struct TrafficSeed {
    pub field_name: String,
    pub type_name: String,
    pub value: String,
    pub source: String,
}

pub fn parse_traffic_file(path: &Path) -> Result<Vec<TrafficSeed>, String> {
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    
    // Check if it's HAR (JSON)
    if let Ok(har) = serde_json::from_str::<HarRoot>(&content) {
        return Ok(extract_from_har(har));
    }

    // TODO: Add Burp XML parsing support
    
    Err("Unsupported traffic file format. Please provide a valid .har file.".to_string())
}

fn extract_from_har(har: HarRoot) -> Vec<TrafficSeed> {
    let mut seeds = Vec::new();

    for entry in har.log.entries {
        if entry.response.status != 200 { continue; }
        
        if let Some(post_data) = entry.request.post_data {
            if let Some(text) = post_data.text {
                if let Ok(json) = serde_json::from_str::<Value>(&text) {
                    // GraphQL often puts variables in a "variables" key
                    if let Some(variables) = json.get("variables").and_then(|v| v.as_object()) {
                        for (key, val) in variables {
                            seeds.push(TrafficSeed {
                                field_name: key.clone(),
                                type_name: "Unknown".to_string(), // Schema mapping happens later
                                value: val.to_string(),
                                source: "HAR Traffic".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    seeds
}
