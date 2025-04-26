use std::{
    fs::{self, File},
    io::{BufReader, Read},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};
use exif::{Tag, Value};
use log::{debug, error};
use reqwest::{header::HeaderMap, Client, Url};
use serde::{Deserialize, Serialize};

use crate::config::Config;

#[derive(Debug, Serialize)]
struct QueryNodeCreateNode {
    kind: String,
    name: String,
    #[serde(rename(serialize = "resourceVersion"))]
    resource_version: String,
    #[serde(rename(serialize = "contentType"))]
    content_type: String,
}

#[derive(Debug, Serialize)]
struct QueryNodeModify {
    op: String,
    value: Vec<String>,
    #[serde(rename(serialize = "resourceVersion"))]
    resource_version: String,
    #[serde(rename(serialize = "contentType"))]
    content_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ResponseAccessToken {
    access_token: String,
    duration: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ResponseEmpty {}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ResponseMatch {
    count: u32,
    r#match: String,
    #[serde(rename(deserialize = "searchData"))]
    search_data: ResponseEmpty,
}

#[derive(Debug, Deserialize, Serialize)]
struct ResponseAggregations {
    #[serde(rename(deserialize = "allPeople"))]
    all_people: Vec<String>,
    #[serde(rename(deserialize = "clusterId"))]
    cluster_id: Vec<String>,
    favorite: Vec<String>,
    location: Vec<String>,
    people: Vec<String>,
    things: Vec<String>,
    time: Vec<ResponseMatch>,
    r#type: Vec<ResponseMatch>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ResponsePicture {
    id: String,
    #[serde(rename(deserialize = "isDefault"))]
    is_default: bool,
    #[serde(rename(deserialize = "ownerId"))]
    owner_id: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ResponseCollectionProperties {
    covers: Vec<ResponsePicture>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResponseSearchData {
    #[serde(rename(deserialize = "accessRuleIds"))]
    access_rule_ids: Vec<String>,
    #[serde(rename(deserialize = "childAssetTypeInfo"))]
    child_asset_type_info: Vec<String>,
    #[serde(default, rename(deserialize = "collectionProperties"))]
    collection_properties: ResponseCollectionProperties,
    #[serde(rename(deserialize = "createdBy"))]
    created_by: String,
    #[serde(rename(deserialize = "createdDate"))]
    created_date: DateTime<Utc>,
    #[serde(default, rename(deserialize = "eTagResponse"))]
    e_tag_response: String,
    #[serde(rename(deserialize = "groupPermissions"))]
    group_permissions: Vec<String>,
    pub id: String,
    #[serde(rename(deserialize = "isRoot"))]
    is_root: bool,
    #[serde(rename(deserialize = "isShared"))]
    is_shared: bool,
    keywords: Vec<String>,
    kind: String,
    labels: Vec<String>,
    #[serde(rename(deserialize = "modifiedDate"))]
    modified_date: DateTime<Utc>,
    #[serde(default)]
    pub name: String,
    #[serde(rename(deserialize = "ownerId"))]
    pub owner_id: String,
    #[serde(rename(deserialize = "parentMap"))]
    parent_map: ResponseEmpty,
    parents: Vec<String>,
    #[serde(rename(deserialize = "protectedFolder"))]
    protected_folder: bool,
    restricted: bool,
    status: String,
    #[serde(rename(deserialize = "subKinds"))]
    sub_kinds: Vec<String>,
    transforms: Vec<String>,
    version: u16,
    #[serde(rename(deserialize = "xAccntParentMap"))]
    x_accnt_parent_map: ResponseEmpty,
    #[serde(rename(deserialize = "xAccntParents"))]
    x_accnt_parents: Vec<String>,
}

impl ResponseSearchData {
    pub fn empty() -> ResponseSearchData {
        let empty_vec: Vec<String> = Vec::new();
            let empty_str: String = "".to_string();
            let empty_chrono: chrono::DateTime<Utc> = chrono::DateTime::<Utc>::from_timestamp_nanos(0);
            let empty_resp = ResponseEmpty{};
            let empty_coll_props = ResponseCollectionProperties{..Default::default()};
            return ResponseSearchData { access_rule_ids: empty_vec.clone(), child_asset_type_info: empty_vec.clone(), collection_properties: empty_coll_props, created_by: empty_str.clone(), created_date: empty_chrono, e_tag_response: empty_str.clone(), group_permissions: empty_vec.clone(), id: empty_str.clone(), is_root: false, is_shared: false, keywords: empty_vec.clone(), kind: empty_str.clone(), labels: empty_vec.clone(), modified_date: empty_chrono, name: empty_str.clone(), owner_id: empty_str.clone(), parent_map: empty_resp.clone(), parents: empty_vec.clone(), protected_folder: false, restricted: false, status: empty_str.clone(), sub_kinds: empty_vec.clone(), transforms: empty_vec.clone(), version: 0, x_accnt_parent_map: empty_resp.clone(), x_accnt_parents: empty_vec.clone() };
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseSearch {
    aggregations: ResponseAggregations,
    pub count: u32,
    pub data: Vec<ResponseSearchData>,
    #[serde(rename(deserialize = "nodeToSearchScoreMap"))]
    node_to_search_score_map: ResponseEmpty,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseNode {
    #[serde(rename(deserialize = "FOLDER"))]
    folder: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseNodes {
    count: u32,
    data: Vec<ResponseSearchData>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseImageProperties {
    orientation: String,
    #[serde(rename(deserialize = "resolutionUnit"))]
    resolution_unit: String,
    width: u32,
    height: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseContentSignature {
    #[serde(rename(deserialize = "contentSignatureType"))]
    content_signature_type: String,
    #[serde(rename(deserialize = "contentSignature"))]
    content_signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseContentProperties {
    size: usize,
    version: u16,
    #[serde(rename(deserialize = "contentType"))]
    content_type: String,
    extension: String,
    md5: String,
    image: ResponseImageProperties,
    #[serde(rename(deserialize = "contentSignatures"))]
    content_signatures: Vec<ResponseContentSignature>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseUpload {
    pub id: String,
    name: String,
    kind: String,
    version: u16,
    #[serde(rename(deserialize = "modifiedDate"))]
    modified_date: DateTime<Utc>,
    #[serde(rename(deserialize = "createdDate"))]
    created_date: DateTime<Utc>,
    parents: Vec<String>,
    #[serde(rename(deserialize = "parentMap"))]
    parent_map: ResponseNode,
    status: String,
    restricted: bool,
    #[serde(rename(deserialize = "protectedFolder"))]
    protected_folder: bool,
    #[serde(rename(deserialize = "contentProperties"))]
    content_properties: ResponseContentProperties,
    properties: ResponseEmpty,
    transforms: Vec<String>,
    keywords: Vec<String>,
    #[serde(rename(deserialize = "ownerId"))]
    owner_id: String,
    #[serde(rename(deserialize = "subKinds"))]
    sub_kinds: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseUploadFail {
    message: String,
    #[serde(rename(deserialize = "errorCode"))]
    error_code: String,
    // Get timestamp as string because of some parsing issues
    #[serde(rename(deserialize = "timeStamp"))]
    time_stamp: String,
    #[serde(rename(deserialize = "requestId"))]
    request_id: String,
    #[serde(rename(deserialize = "errorDetails"))]
    error_details: ResponseUploadFailDetails,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseUploadFailDetails {
    #[serde(rename(deserialize = "conflictNodeIds"))]
    conflict_node_ids: Vec<String>,
}

#[derive(Debug)]
pub struct AmznPhoto {
    conf: Config,
    web_dir_node: Option<ResponseSearchData>,
    client: Client,
    dry_run: bool,
}

impl AmznPhoto {
    pub fn new(conf: &Config, dry_run: bool) -> Self {
        Self {
            conf: conf.clone(),
            web_dir_node: None,
            client: Client::new(),
            dry_run: dry_run,
        }
    }

    fn get_epoch_millis() -> String {
        let systime = SystemTime::now();
        let since_epoch = systime
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        since_epoch.as_millis().to_string()
    }

    /// Get an auth token valid across all Amazon boundaries - Used for content uploading
    #[allow(dead_code)]
    async fn renew_auth_token(&mut self) -> Result<&str, reqwest::Error> {
        let url = Url::parse(
            format!("https://www.amazon.{}/photos/auth/token", self.conf.country).as_str(),
        )
        .expect("Can't parse the token renewal URL");

        // Provide timestamp as a parameter
        let params = [("_", AmznPhoto::get_epoch_millis())];
        let mut headers = HeaderMap::new();
        headers.append("Content-Type", "application/json".parse().unwrap());
        headers.append(
            "Accept",
            "application/json, text/javascript, */*; q=0.01"
                .parse()
                .unwrap(),
        );
        headers.append("User-Agent", self.conf.user_agent.parse().unwrap());
        headers.append(
            "Cookie",
            format!(
                "session-id={}; x-acb{}={}; at-acb{}={}; ubid-acb{}={}",
                self.conf.session_id,
                self.conf.country,
                self.conf.cookie_x_acb,
                self.conf.country,
                self.conf.cookie_at_acb,
                self.conf.country,
                self.conf.cookie_ubid_acb
            )
            .parse()
            .unwrap(),
        );
        headers.append("x-amzn-SessionId", self.conf.session_id.parse().unwrap());

        // Stop early
        if self.dry_run {
            debug!("Dry-run, give back fake data");
            return Ok("");
        }

        // Submit the GET request
        let response = self
            .client
            .get(url)
            .headers(headers)
            .query(&params)
            .send()
            .await?;

        // Check the HTTP status
        if response.status().is_success() {
            let body = response.json::<ResponseAccessToken>().await?;
            // debug!(
            //     "Access token, valid {} seconds:{}",
            //     body.duration, body.access_token
            // );
            self.conf.cookie_x_amz_access_token = body.access_token;
            Ok(&self.conf.cookie_x_amz_access_token)
        } else {
            debug!("Request failed with status: {}", response.status());
            Err(response.error_for_status().err().unwrap())
        }
    }

    async fn list_albums(&self) -> Result<ResponseSearch, reqwest::Error> {
        self.search(format!("?asset=ALL&filters=type%3A(ALBUMS)&limit=200&lowResThumbnail=true&searchContext=customer&sort=%5B%27createdDate+DESC%27%5D&tempLink=false&resourceVersion=V2&ContentType=JSON&_={}", AmznPhoto::get_epoch_millis()).as_str()).await
    }

    async fn create_album(&self, name: &str) -> Result<ResponseSearchData, reqwest::Error> {
        let url =
            Url::parse(format!("https://www.amazon.{}/drive/v1/nodes", self.conf.country).as_str())
                .expect("Can't parse the create album URL");

        let mut headers = HeaderMap::new();
        headers.append("Content-Type", "application/json".parse().unwrap());
        headers.append(
            "Accept",
            "application/json, text/javascript, */*; q=0.01"
                .parse()
                .unwrap(),
        );
        headers.append("User-Agent", self.conf.user_agent.parse().unwrap());
        headers.append(
            "Cookie",
            format!(
                "session-id={}; x-acb{}={}; at-acb{}={}; ubid-acb{}={}",
                self.conf.session_id,
                self.conf.country,
                self.conf.cookie_x_acb,
                self.conf.country,
                self.conf.cookie_at_acb,
                self.conf.country,
                self.conf.cookie_ubid_acb
            )
            .parse()
            .unwrap(),
        );
        headers.append("x-amzn-SessionId", self.conf.session_id.parse().unwrap());
        let payload = QueryNodeCreateNode {
            kind: "VISUAL_COLLECTION".to_string(),
            name: name.to_string(),
            resource_version: "V2".to_string(),
            content_type: "JSON".to_string(),
        };

        // Return early
        if self.dry_run {
            debug!("Dry-run, return fake data");
            return Ok(ResponseSearchData::empty());
        }

        // Submit the POST request
        let response = self
            .client
            .post(url)
            .headers(headers)
            .json(&payload)
            .send()
            .await?;

        // Check the HTTP status
        if response.status().is_success() {
            let body = response.json::<ResponseSearchData>().await?;
            Ok(body)
        } else {
            debug!("Request failed with status: {}", response.status());
            Err(response.error_for_status().err().unwrap())
        }
    }

    /// Get a reference to an album by name, create it if needed
    pub async fn get_album(&self, name: &str) -> Result<ResponseSearchData, reqwest::Error> {
        let existing_albums = self.list_albums().await.unwrap();
        debug!("Got {} existing albums:", existing_albums.count);
        for album in existing_albums.data {
            debug!("\t{}", album.name);
            if album.name == name {
                return Ok(album);
            }
        }

        self.create_album(name).await
    }

    async fn search(&self, query: &str) -> Result<ResponseSearch, reqwest::Error> {
        let url = Url::parse(
            format!(
                "https://www.amazon.{}/drive/v1/search{}",
                self.conf.country, query
            )
            .as_str(),
        )
        .expect("Can't parse the search URL");

        let mut headers = HeaderMap::new();
        headers.append("Content-Type", "application/json".parse().unwrap());
        headers.append(
            "Accept",
            "application/json, text/javascript, */*; q=0.01"
                .parse()
                .unwrap(),
        );
        headers.append("User-Agent", self.conf.user_agent.parse().unwrap());
        headers.append(
            "Cookie",
            format!(
                "session-id={}; x-acb{}={}; at-acb{}={}; ubid-acb{}={}",
                self.conf.session_id,
                self.conf.country,
                self.conf.cookie_x_acb,
                self.conf.country,
                self.conf.cookie_at_acb,
                self.conf.country,
                self.conf.cookie_ubid_acb
            )
            .parse()
            .unwrap(),
        );
        headers.append("x-amzn-SessionId", self.conf.session_id.parse().unwrap());

        // Return early
        if self.dry_run {
            debug!("Dry run, return fake data");
            let empty_vec_str: Vec<String> = Vec::new();
            let empty_vec_respmatch: Vec<ResponseMatch> = Vec::new();
            let empty_vec_respdata: Vec<ResponseSearchData> = Vec::new();
            return Ok(ResponseSearch{count: 0, aggregations: ResponseAggregations{all_people: empty_vec_str.clone(), cluster_id: empty_vec_str.clone(), favorite: empty_vec_str.clone(), location: empty_vec_str.clone(), people: empty_vec_str.clone(), things: empty_vec_str.clone(), time: empty_vec_respmatch.clone(), r#type: empty_vec_respmatch.clone()}, data: empty_vec_respdata, node_to_search_score_map: ResponseEmpty{}});
        }

        // Submit the GET request
        let response = self.client.get(url).headers(headers).send().await?;

        // Check the HTTP status
        if response.status().is_success() {
            let body = response.json::<ResponseSearch>().await?;
            debug!("Search response: {:?}", body);
            Ok(body)
        } else {
            debug!("Request failed with status: {}", response.status());
            Err(response.error_for_status().err().unwrap())
        }
    }

    async fn find_root_node(&self) -> ResponseSearchData {
        match self.find_nodes("isRoot:true").await {
            Ok(n) => {
                if n.data.len() < 1 {
                    error!("No nodes!");
                    return ResponseSearchData::empty();
                }
                n.data.first().unwrap().clone()
            },
            Err(e) => {
                error!("Error {:?}", e);
                panic!("{:?}", e);
            }
        }
    }

    async fn update_web_pictures_dir_node(&mut self) -> ResponseSearchData {
        let root_node = self.find_root_node().await;
        let pictures_dir_searchdata = self
            .find_children_nodes(
                "kind:FOLDER+AND+status:(AVAILABLE*)+AND+name:\"Pictures\"",
                &root_node.id,
            )
            .await
            .unwrap();
        let pictures_dir = pictures_dir_searchdata.data.get(0).unwrap();
        let web_dir_node = self
            .find_children_nodes(
                "kind:FOLDER+AND+status:(AVAILABLE*)+AND+name:\"Web\"",
                &pictures_dir.id,
            )
            .await
            .unwrap()
            .data
            .get(0)
            .unwrap()
            .clone();
        self.web_dir_node = Some(web_dir_node.clone());
        web_dir_node
    }

    async fn find_children_nodes(
        &self,
        filter: &str,
        node_id: &str,
    ) -> Result<ResponseNodes, reqwest::Error> {
        let url = Url::parse(format!("https://www.amazon.{}/drive/v1/nodes/{}/children?asset=ALL&filters={}&searchOnFamily=false&tempLink=false&offset=0&resourceVersion=V2&ContentType=JSON&_={}", self.conf.country, node_id, filter, AmznPhoto::get_epoch_millis()).as_str()).expect("Can't parse children nodes URL");
        let params = [];
        self.find_nodes_internal(url, &params).await
    }

    async fn find_nodes(&self, filter: &str) -> Result<ResponseNodes, reqwest::Error> {
        let url = Url::parse(
            format!("https://www.amazon.{}/drive/v1/nodes/", self.conf.country).as_str(),
        )
        .expect("Can't parse the find node URL");
        let epoch = AmznPhoto::get_epoch_millis();
        let params = [
            ("filters", filter),
            ("resourceVersion", "V2"),
            ("ContentType", "JSON"),
            ("_", epoch.as_str()),
        ];
        self.find_nodes_internal(url, &params).await
    }

    async fn find_nodes_internal(
        &self,
        url: Url,
        params: &[(&str, &str)],
    ) -> Result<ResponseNodes, reqwest::Error> {
        let mut headers = HeaderMap::new();
        headers.append("Content-Type", "application/json".parse().unwrap());
        headers.append(
            "Accept",
            "application/json, text/javascript, */*; q=0.01"
                .parse()
                .unwrap(),
        );
        headers.append("User-Agent", self.conf.user_agent.parse().unwrap());
        headers.append(
            "Cookie",
            format!(
                "session-id={}; x-acb{}={}; at-acb{}={}; ubid-acb{}={}",
                self.conf.session_id,
                self.conf.country,
                self.conf.cookie_x_acb,
                self.conf.country,
                self.conf.cookie_at_acb,
                self.conf.country,
                self.conf.cookie_ubid_acb
            )
            .parse()
            .unwrap(),
        );
        headers.append("x-amzn-SessionId", self.conf.session_id.parse().unwrap());

        // Return early
        if self.dry_run {
            let respdata: Vec<ResponseSearchData> = Vec::new();
            return Ok(ResponseNodes{ count: 0, data: respdata });
        }

        // Submit the POST request
        let response = self
            .client
            .get(url)
            .headers(headers)
            .query(&params)
            .send()
            .await?;

        // Check the HTTP status
        if response.status().is_success() {
            let body = response.json::<ResponseNodes>().await?;
            debug!("Found nodes: {:?}", body.data);
            Ok(body)
        } else {
            debug!("Request failed with status: {}", response.status());
            Err(response.error_for_status().err().unwrap())
        }
    }

    /// Upload a picture and return its ID
    pub async fn upload_picture(&mut self, pic_path: &Path) -> Result<String, reqwest::Error> {
        if self.web_dir_node.is_none() && !self.dry_run {
            self.update_web_pictures_dir_node().await;
        }

        let attr = fs::metadata(pic_path).unwrap();
        // Get EXIF data
        let file = File::open(pic_path).unwrap();
        let mut contents = BufReader::new(file);
        let exif_reader = exif::Reader::new();
        let exif_data = exif_reader.read_from_container(&mut contents).unwrap();
        let capture_date: exif::DateTime;
        if let Some(field) = exif_data.get_field(Tag::DateTimeDigitized, exif::In::PRIMARY) {
            match field.value {
                Value::Ascii(ref vec) if !vec.is_empty() => {
                    capture_date = exif::DateTime::from_ascii(&vec[0]).unwrap();
                }
                _ => capture_date = exif::DateTime::from_ascii(b"2000:01:01 00:00:00").unwrap(),
            }
        } else {
            capture_date = exif::DateTime::from_ascii(b"2000:01:01 00:00:00").unwrap();
        }
        let capture_date_str = format!(
            "{:0>4}-{:0>2}-{:0>2}T{:0>2}:{:0>2}:{:0>2}.{:0>3}Z",
            capture_date.year,
            capture_date.month,
            capture_date.day,
            capture_date.hour,
            capture_date.minute,
            capture_date.second,
            capture_date.nanosecond.or_else(|| Some(0)).unwrap()
        );
        let mut contents_vec: Vec<u8> = Vec::with_capacity(attr.len() as usize);
        // Now get contents
        let mut file = File::open(pic_path).unwrap();
        let _ = file.read_to_end(&mut contents_vec);
        // Finally, get hash
        let md5sum = md5::compute(&contents_vec);

        let parent_node = match self.dry_run {
            false => &self.web_dir_node.as_ref().unwrap().id,
            true => "NONE"
        };

        let url = Url::parse(
            format!(
                "https://content-{}.drive.amazonaws.com/v2/upload?conflictResolution=RENAME&fileSize={}&name={}&parentNodeId={}&contentDate={}",
                self.conf.zone,
                &attr.len().to_string(),
                pic_path.file_name().unwrap().to_str().unwrap(),
                parent_node,
                &capture_date_str
            )
            .as_str(),
        )
        .expect("Can't parse the upload URL");

        let mut headers = HeaderMap::new();
        headers.append(
            "Content-Type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        headers.append(
            "Accept",
            "application/json, text/plain, */*".parse().unwrap(),
        );
        headers.append("User-Agent", self.conf.user_agent.parse().unwrap());
        headers.append("x-amzn-file-md5", format!("{:x}", md5sum).parse().unwrap());
        headers.append(
            "Cookie",
            format!(
                "session-id={}; x-acb{}={}; at-acb{}={}; ubid-acb{}={}",
                self.conf.session_id,
                self.conf.country,
                self.conf.cookie_x_acb,
                self.conf.country,
                self.conf.cookie_at_acb,
                self.conf.country,
                self.conf.cookie_ubid_acb
            )
            .parse()
            .unwrap(),
        );
        headers.append("x-amzn-SessionId", self.conf.session_id.parse().unwrap());

        // Return early
        if self.dry_run {
            return Ok("".to_string());
        }

        // Submit the POST request
        let response = self
            .client
            .post(url)
            .headers(headers)
            .body(contents_vec)
            .send()
            .await?;

        // Check the HTTP status
        if response.status().is_success() {
            let body = response.json::<ResponseUpload>().await?;
            Ok(body.id)
        } else {
            let status_code = response.status().as_u16();
            debug!("Upload failed on status code {}", status_code);
            match status_code {
                // Ignore double-uploads
                409 => {
                    // let body = response.text().await?;
                    // debug!("{:?}", body);
                    // panic!();
                    let body = response.json::<ResponseUploadFail>().await?;
                    Ok(body
                        .error_details
                        .conflict_node_ids
                        .first()
                        .unwrap()
                        .to_string())
                }
                _ => {
                    let body = response.text().await?;
                    debug!("{:?}", body);
                    panic!();
                    // debug!("Request failed with status: {}", status_code);
                    // Err(response.error_for_status().err().unwrap())
                }
            }
        }
    }

    pub async fn add_to_album(
        &self,
        album_id: String,
        uploaded_ids: &[String],
    ) -> Result<(), reqwest::Error> {
        let url = Url::parse(
            format!(
                "https://www.amazon.{}/drive/v1/nodes/{}/children",
                self.conf.country, album_id
            )
            .as_str(),
        )
        .expect("Can't parse the add to album URL");

        let mut headers = HeaderMap::new();
        headers.append(
            "Content-Type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        headers.append(
            "Accept",
            "application/json, text/plain, */*".parse().unwrap(),
        );
        headers.append("User-Agent", self.conf.user_agent.parse().unwrap());
        headers.append(
            "Cookie",
            format!(
                "session-id={}; x-acb{}={}; at-acb{}={}; ubid-acb{}={}",
                self.conf.session_id,
                self.conf.country,
                self.conf.cookie_x_acb,
                self.conf.country,
                self.conf.cookie_at_acb,
                self.conf.country,
                self.conf.cookie_ubid_acb
            )
            .parse()
            .unwrap(),
        );
        headers.append("x-amzn-SessionId", self.conf.session_id.parse().unwrap());

        let payload = QueryNodeModify {
            op: "add".to_string(),
            value: uploaded_ids.to_vec(),
            resource_version: "V2".to_string(),
            content_type: "JSON".to_string(),
        };

        // Return early
        if self.dry_run {
            return Ok(());
        }

        // Submit the PATCH request
        let response = self
            .client
            .patch(url)
            .headers(headers)
            .json(&payload)
            .send()
            .await?;

        // Check the HTTP status
        if response.status().is_success() {
            Ok(())
        } else {
            let status_code = response.status().as_u16();
            debug!("Request failed with status: {}", status_code);
            Err(response.error_for_status().err().unwrap())
        }
    }
}
