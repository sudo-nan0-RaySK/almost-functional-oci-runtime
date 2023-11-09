use std::collections::HashMap;
use std::ffi::CString;
use std::io::Cursor;
use std::process::Output;
use std::str;

use anyhow::{Context, Result};
#[cfg(any(target_os = "linux"))]
use nix::sched::CloneFlags;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::ManifestResponseTypes::ManifestImageResponseType;

const HEADER_WWW_AUTHENTICATE: &'static str = "www-authenticate";
const HEADER_SERVICE: &'static str = "service";
const HEADER_SCOPE: &'static str = "scope";
const HEADER_INDEX_MANIFEST_ACCEPT_CONTENT_V2_OR_JSON: &'static str =
    "application/vnd.docker.distribution.manifest.v2+json";
const HEADER_INDEX_MANIFEST_CONTENT_V1_OR_JSON: &'static str =
    "application/vnd.oci.image.index.v1+json";
const HEADER_INDEX_MANIFEST_CONTENT_V2_OR_JSON: &'static str =
    "application/vnd.oci.image.index.v2+json";
const HEADER_IMAGE_MANIFEST_V1_CONTENT_OR_JSON: &'static str =
    "application/vnd.oci.image.manifest.v1+json";
const HEADER_IMAGE_CONTENT_V1_ALL: &'static str =
    "application/vnd.oci.image.layer.v1.tar+vnd.oci.image.layer.nondistributable.v1.tar+gzip";

// Usage: your_docker.sh run <image> <command> <arg1> <arg2> ...

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let command = &args[3];
    let command_args = &args[4..];
    let image = &args[2];
    let image_parts: Vec<&str> = image.split(":").collect();
    let image_name = image_parts[0];
    let image_tag = if image_parts.len() >= 2 {
        image_parts[1..].join(":")
    } else {
        "latest".to_string()
    };

    // Creating jail directory
    let _ = exec_command_and_get_output("mkdir", &vec![String::from("jail")]);

    // Pull OCI Image
    pull_container_image(image_name, &image_tag)?;

    setup_chroot_jail();
    #[cfg(any(target_os = "linux"))]
    unshare_namespaces();

    let output = exec_command_and_get_output(command, &Vec::from(command_args));

    let stdout_contents = str::from_utf8(output.stdout.as_slice())?;
    let stderr_contents = str::from_utf8(output.stderr.as_slice())?;

    print!("{}", stdout_contents);
    eprint!("{}", stderr_contents);

    let child_exit_code = output.status.code().unwrap();
    if !output.status.success() {
        std::process::exit(child_exit_code);
    }

    Ok(())
}

fn pull_container_image(image_name: &str, image_tag: &str) -> Result<()> {
    let manifest_pull_url =
        format!("https://registry.hub.docker.com/v2/library/{image_name}/manifests/{image_tag}");
    let client = Client::new();
    let response = client
        .get(&manifest_pull_url)
        .send()?;

    match response.status() {
        StatusCode::UNAUTHORIZED => {
            let www_authenticate_resp_header =
                response.headers().get(HEADER_WWW_AUTHENTICATE).unwrap().to_str()?;
            let (bearer_realm, service, scope) =
                break_www_authenticate_header_into_parts(www_authenticate_resp_header);
            let token_response = obtain_auth_token(&client, bearer_realm, service, scope)?;
            let manifest_result =
                get_manifest_file(
                    &client,
                    image_name,
                    image_tag,
                    token_response.token.clone())?;
            match manifest_result {
                ManifestResponseTypes::ManifestIndexResponseType(manifests) => {
                    use_manifest_matching_platform(
                        &client,
                        image_name,
                        token_response.token.clone(),
                        &manifests,
                    )?;
                }
                ManifestResponseTypes::ManifestImageResponseType(image_manifest_response) => {
                    download_and_extract_layers(
                        &client,
                        image_name,
                        token_response.token.clone(),
                        image_manifest_response)?;
                }
            }
        }
        _ => {
            todo!("Error handling on initial manifest pull try")
        }
    }
    Ok(())
}

fn get_manifest_file(
    client: &Client,
    image_name: &str,
    image_tag: &str,
    token: String,
) -> Result<ManifestResponseTypes, anyhow::Error> {
    let manifest_pull_url =
        format!("https://registry.hub.docker.com/v2/library/{image_name}/manifests/{image_tag}");
    let manifest_response_raw = client.get(manifest_pull_url)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(ACCEPT, HEADER_INDEX_MANIFEST_ACCEPT_CONTENT_V2_OR_JSON)
        .send()?;
    match manifest_response_raw.status() {
        StatusCode::OK => {
            let manifest_response_headers = manifest_response_raw.headers().clone();
            let content_type_header = manifest_response_headers.
                get(CONTENT_TYPE).unwrap().to_str().unwrap();
            if is_index_manifest_type(content_type_header) {
                let manifest_response: ManifestIndexResponse = manifest_response_raw.json()?;
                let mut manifests = manifest_response.manifests.clone();
                let image_manifests: &mut Vec<ManifestItem> = manifests.as_mut();
                image_manifests.retain(
                    |manifest_item|
                        !is_index_manifest_type(manifest_item.media_type.as_str()));

                let mut manifests = manifest_response.manifests.clone();
                let nested_index_manifests: &mut Vec<ManifestItem> = manifests.as_mut();
                nested_index_manifests.retain(
                    |manifest_item|
                        is_index_manifest_type(manifest_item.media_type.as_str()));

                for manifest in nested_index_manifests.iter() {
                    let nested_image_manifests_response = get_manifest_file(
                        client,
                        image_name,
                        manifest.digest.as_str(),
                        token.clone())?;
                    match nested_image_manifests_response {
                        ManifestResponseTypes::ManifestIndexResponseType(nested_image_manifests) => {
                            image_manifests.extend(nested_image_manifests)
                        }
                        _ => {
                            unreachable!()
                        }
                    }
                }
                Ok(ManifestResponseTypes::ManifestIndexResponseType(image_manifests.to_vec()))
            } else {
                let manifest_response: ManifestImageResponse = manifest_response_raw.json()?;
                Ok(ManifestImageResponseType(manifest_response))
            }
        }
        non_200_status_code => {
            Err(anyhow::Error::msg(
                format!("Non zero status code received => {non_200_status_code}")))
        }
    }
}

fn is_index_manifest_type(media_or_content_type: &str) -> bool {
    media_or_content_type.contains(HEADER_INDEX_MANIFEST_CONTENT_V1_OR_JSON)
        || media_or_content_type.contains(HEADER_INDEX_MANIFEST_CONTENT_V2_OR_JSON)
}

fn use_manifest_matching_platform(client: &Client,
                                  image_name: &str,
                                  token: String,
                                  manifests: &Vec<ManifestItem>) -> Result<()> {
    // TODO(sudo-nan0-RaySK): Support all architectures/platforms
    let os = "linux";
    let arch = "amd64";
    if manifests.len() == 0 {
        panic!("No image manifest found! Empty manifest list!");
    }
    let chosen_manifest = if manifests.len() == 1 {
        &manifests[0]
    } else {
        // TODO(sudo-nan0-RaySK): Follow the spec properly
        manifests.iter().filter(|manifest_item| {
            manifest_item.platform().as_ref().unwrap().architecture().contains(arch)
                && manifest_item.platform().as_ref().unwrap().os().contains(os)
        }).collect::<Vec<&ManifestItem>>().first()
            .expect("No matching image manifest found!")
    };
    let digest = chosen_manifest.digest.as_str();
    let image_manifest_download_url =
        format!(
            "https://registry.hub.docker.com/v2/library/{image_name}/manifests/{digest}"
        );
    let image_manifest_response_raw = client
        .get(image_manifest_download_url)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header(ACCEPT, HEADER_IMAGE_MANIFEST_V1_CONTENT_OR_JSON)
        .send()?;
    match image_manifest_response_raw.status() {
        StatusCode::OK => {
            let image_manifest_response: ManifestImageResponse =
                image_manifest_response_raw.json()?;
            download_and_extract_layers(client, image_name, token, image_manifest_response)?;
        }
        non_200_status_code => {
            panic!("Received non 200 exit code ({non_200_status_code})");
        }
    };
    Ok(())
}

fn download_and_extract_layers(
    client: &Client,
    image_name: &str,
    token: String,
    image_manifest_response: ManifestImageResponse,
) -> Result<()> {
    let layer_digests: Vec<&str> = image_manifest_response.layers.iter()
        .map(|descriptor| descriptor.digest.as_str())
        .clone()
        .collect();
    // TODO(sudo-nan0-RaySK): Apply the operations too apart from just downloading
    //  and extracting to obey spec
    download_and_extract_layers_helper(client, image_name, token, layer_digests)?;
    Ok(())
}

fn download_and_extract_layers_helper(
    client: &Client,
    image_name: &str,
    token: String,
    layer_digests: Vec<&str>,
) -> Result<()> {
    // TODO(sudo-nan0-RaySK): Handle this in parallel
    for layer_digest in layer_digests {
        let image_layer_download_url =
            format!(
                "https://registry.hub.docker.com/v2/library/{image_name}/blobs/{layer_digest}"
            );
        let image_layer_response = client
            .get(image_layer_download_url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(ACCEPT, HEADER_IMAGE_CONTENT_V1_ALL)
            .send()?;
        match image_layer_response.status() {
            StatusCode::OK => {
                let sanitized_layer_file_name = layer_digest.strip_prefix("sha256:")
                    .unwrap();
                let sanitized_layer_file_name = format!("jail/{sanitized_layer_file_name}");
                let mut layer_file = std::fs::File::create(
                    sanitized_layer_file_name.as_str()
                )?;
                let mut content = Cursor::new(image_layer_response.bytes()?);
                std::io::copy(&mut content, &mut layer_file)?;
                _ = exec_command_and_get_output(
                    "tar",
                    &vec![
                        String::from("-xvzf"),
                        String::from(sanitized_layer_file_name.as_str()),
                        String::from("--directory=jail"),
                    ]);
                std::fs::remove_file(sanitized_layer_file_name.as_str())?;
            }
            non_200_status_code => {
                panic!("Received non 200 exit code ({non_200_status_code})");
            }
        };
    }
    Ok(())
}

fn obtain_auth_token(
    client: &Client,
    bearer_realm: &str,
    service: &str,
    scope: &str) -> Result<TokenAuthResponse, anyhow::Error> {
    let response = client.get(bearer_realm)
        .query(&[(HEADER_SERVICE, service)])
        .query(&[(HEADER_SCOPE, scope)])
        .send()?;
    match response.status() {
        StatusCode::OK => {
            Ok(response.json()?)
        }
        status_code => {
            Err(anyhow::Error::msg(
                format!(
                    "Error in obtaining auth token, received status code => {:?}",
                    status_code
                )
            ))
        }
    }
}

fn break_www_authenticate_header_into_parts(header_val: &str) -> (&str, &str, &str) {
    let header_raw_parts: &mut Vec<&str> = &mut header_val.split(',').collect();
    let parts: Vec<&str> = header_raw_parts.iter_mut().map(|header_part| {
        let individual_raw_part: Vec<&str> = header_part.split('=').collect();
        assert_eq!(individual_raw_part.len(), 2);
        individual_raw_part[1].
            strip_prefix('\"').unwrap()
            .strip_suffix('\"').unwrap()
    }).collect();
    assert_eq!(parts.len(), 3);
    (parts[0], parts[1], parts[2])
}

#[cfg(any(target_os = "linux"))]
fn unshare_namespaces() {
    use nix::sched::unshare;
    unshare(CloneFlags::CLONE_NEWPID)
        .expect("Error while calling unshare(CLONE_NEWPID)");
}

fn setup_chroot_jail() {
    // TODO(sudo-nan0_RaySK): Fix this heap allocation and cloning of these args later
    _ = exec_command_and_get_output("mkdir",
                                    &vec![
                                        String::from("-p"),
                                        String::from("jail/usr/local/bin"),
                                    ]);
    _ = exec_command_and_get_output("cp",
                                    &vec![
                                        String::from("/usr/local/bin/docker-explorer"),
                                        String::from("jail/usr/local/bin"),
                                    ]);
    _ = exec_command_and_get_output("mkdir", &vec![String::from("jail/proc")]);
    _ = exec_command_and_get_output("mkdir", &vec![String::from("jail/dev")]);
    _ = exec_command_and_get_output("touch", &vec![String::from("jail/dev/null")]);
    _ = exec_command_and_get_output("chmod",
                                    &vec![
                                        String::from("666"),
                                        String::from("jail/dev/null"),
                                    ]);
    _ = exec_command_and_get_output("mount",
                                    &vec![
                                        String::from("-B"),
                                        String::from("/proc"),
                                        String::from("jail/proc"),
                                    ]);
    // Setting up `chroot` jail
    let jail_path = CString::new("jail").unwrap();
    unsafe {
        let exit_code = libc::chroot(jail_path.as_ptr());
        if !(exit_code == 0i32) {
            eprintln!("Error executing libc::chroot('jail'), exit code => {:?}", exit_code);
            std::process::exit(exit_code as i32);
        }
        let exit_code = libc::chdir(jail_path.as_ptr());
        if !(exit_code == 0i32) {
            eprintln!("Error executing libc::chdir('jail'), exit code => {:?}", exit_code);
            std::process::exit(exit_code as i32);
        }
    }
}

fn exec_command_and_get_output(command: &str, args: &Vec<String>) -> Output {
    std::process::Command::new(command).args(args).output().with_context(|| {
        format!(
            "Tried to run '{}' with arguments {:?}",
            command, args
        )
    }).unwrap()
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenAuthResponse {
    token: String,
    expires_in: u32,
    issued_at: String,
}

enum ManifestResponseTypes {
    ManifestIndexResponseType(Vec<ManifestItem>),
    ManifestImageResponseType(ManifestImageResponse),
}

#[derive(Serialize, Deserialize, Debug)]
struct ManifestIndexResponse {
    #[serde(rename = "schemaVersion")]
    schema_version: u16,
    #[serde(rename = "mediaType")]
    media_type: String,
    #[serde(rename = "artifactType")]
    artifact_type: Option<String>,
    manifests: Vec<ManifestItem>,
    subject: Option<Descriptor>,
    annotations: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ManifestImageResponse {
    #[serde(rename = "schemaVersion")]
    schema_version: u16,
    #[serde(rename = "mediaType")]
    media_type: String,
    #[serde(rename = "artifactType")]
    artifact_type: Option<String>,
    // TODO(sudo-nan0-RaySK): Follow spec and apply config operations after extracting layers
    config: Descriptor,
    // TODO(sudo-nan0-RaySK): Apply whiteouts apart from simply extracting layers if
    //    layer's media type is 'application/vnd.oci.image.layer.v1.tar' or if config.mediaType is
    //    'application/vnd.oci.image.config.v1+json'
    layers: Vec<Descriptor>,
    subject: Option<Descriptor>,
    annotations: Option<HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ManifestItem {
    #[serde(rename = "mediaType")]
    media_type: String,
    platform: Option<Platform>,
    digest: String,
    size: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Platform {
    architecture: String,
    os: String,
    #[serde(rename = "os.version")]
    os_version: Option<String>,
    #[serde(rename = "os.features")]
    os_features: Option<Vec<String>>,
    variant: Option<String>,
    features: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Descriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    size: u64,
    urls: Option<Vec<String>>,
    annotations: Option<HashMap<String, String>>,
    data: Option<String>,
    #[serde(rename = "artifactType")]
    artifact_type: Option<String>,
}

impl ManifestItem {
    pub fn platform(&self) -> &Option<Platform> {
        &self.platform
    }
}

impl Platform {
    pub fn os(&self) -> &String {
        &self.os
    }

    pub fn architecture(&self) -> &String {
        &self.architecture
    }
}
