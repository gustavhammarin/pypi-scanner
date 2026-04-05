use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Serialize, Deserialize, Debug)]
pub struct PypiResponse {
    pub info: PypiRequirements,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PypiRequirements {
    pub requires_dist: Vec<String>,
    pub requires_python: Option<String>,
}

pub async fn get_requires_dist(
    client: &reqwest::Client,
    package_id: &str,
    version: &str,
) -> Result<PypiRequirements, AppError> {
    let url = format!("https://pypi.org/pypi/{package_id}/{version}/json");
    let json: PypiResponse = client.get(url).send().await?.json().await?;
    Ok(json.info)
}

use tempfile::TempDir;

pub async fn download_package_source(package: &str, version: &str) -> Result<TempDir, AppError> {
    let url = format!("https://pypi.org/pypi/{}/{}/json", package, version);
    let client = reqwest::Client::new();
    let meta: serde_json::Value = client.get(&url).send().await?.json().await?;

    let sdist_url = meta["urls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["packagetype"] == "sdist")
        .and_then(|u| u["url"].as_str())
        .ok_or(AppError::NotFound("no sdist found".into()))?;

    let tmp_dir = tempfile::tempdir()?;
    
    let tarball_bytes = client.get(sdist_url).send().await?.bytes().await?;
    let tarball_path = tmp_dir.path().join("source.tar.gz");
    std::fs::write(&tarball_path, &tarball_bytes)?;

    let tar_gz = std::fs::File::open(&tarball_path)?;
    let tar = flate2::read::GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(tar);
    archive.unpack(tmp_dir.path())?;

    Ok(tmp_dir) // TempDir rensas automatiskt när den droppas
}


#[tokio::test]
async fn test_get_requires_dist() {
    let client = reqwest::Client::new();
    let requires_dist = get_requires_dist(&client, "twine", "4.0.2").await.unwrap();
    println!("{:?}", requires_dist)
}
