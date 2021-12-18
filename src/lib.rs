extern crate json;
extern crate ureq;

#[derive(Clone, Copy)]
enum MetadataUrls {
    InstanceId,
    AmiId,
    AccountId,
    AvailabilityZone,
    InstanceType,
    Hostname,
    LocalHostname,
    PublicHostname,
    SpotInstanceAction,
}

impl Into<&'static str> for MetadataUrls {
    fn into(self) -> &'static str {
        match self {
            MetadataUrls::InstanceId => "http://169.254.169.254/latest/meta-data/instance-id",
            MetadataUrls::AmiId => "http://169.254.169.254/latest/meta-data/ami-id",
            MetadataUrls::AccountId => {
                "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info"
            }
            MetadataUrls::AvailabilityZone => {
                "http://169.254.169.254/latest/meta-data/placement/availability-zone"
            }
            MetadataUrls::InstanceType => "http://169.254.169.254/latest/meta-data/instance-type",
            MetadataUrls::Hostname => "http://169.254.169.254/latest/meta-data/hostname",
            MetadataUrls::LocalHostname => "http://169.254.169.254/latest/meta-data/local-hostname",
            MetadataUrls::PublicHostname => {
                "http://169.254.169.254/latest/meta-data/public-hostname"
            },
            MetadataUrls::SpotInstanceAction => {
                "http://169.254.169.254/latest/meta-data/spot/instance-action"
            },
        }
    }
}

fn identity_credentials_to_account_id(ident_creds: &str) -> Result<String> {
    let parsed = json::parse(ident_creds)?;
    Ok(parsed["AccountId"].to_string())
}

fn availability_zone_to_region(availability_zone: &str) -> Result<&'static str> {
    const REGIONS: &[&str] = &[
        "ap-south-1",
        "eu-west-3",
        "eu-north-1",
        "eu-west-2",
        "eu-west-1",
        "ap-northeast-3",
        "ap-northeast-2",
        "ap-northeast-1",
        "sa-east-1",
        "ca-central-1",
        "ap-southeast-1",
        "ap-southeast-2",
        "eu-central-1",
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "cn-north-1",
        "cn-northwest-1",
    ];

    for region in REGIONS {
        if availability_zone.starts_with(region) {
            return Ok(region);
        }
    }

    Err(Error::UnknownAvailabilityZone(
        availability_zone.to_string(),
    ))
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub enum Error {
    HttpRequest(String),
    IoError(String),
    UnknownAvailabilityZone(String),
    JsonError(String),
    NotFound(&'static str), // Reported for static URIs we fetch.
}

impl From<ureq::Error> for Error {
    fn from(error: ureq::Error) -> Error {
        Error::HttpRequest(format!("{:?}", error))
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error::IoError(format!("{:?}", error))
    }
}

impl From<json::Error> for Error {
    fn from(error: json::Error) -> Error {
        Error::JsonError(format!("{:?}", error))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::HttpRequest(s) => write!(f, "Http Request Error: {}", s),
            Error::IoError(s) => write!(f, "IO Error: {}", s),
            Error::UnknownAvailabilityZone(s) => write!(f, "Unknown AvailabilityZone: {}", s),
            Error::JsonError(s) => write!(f, "JSON parsing error: {}", s),
            Error::NotFound(s) => write!(f, "Not found: {}", s),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// `InstanceMetadataClient` provides an API for fetching common fields
/// from the EC2 Instance Metadata API: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
///
/// # Examples:
/// ```
/// use ec2_instance_metadata::InstanceMetadataClient;
/// let client = ec2_instance_metadata::InstanceMetadataClient::new();
/// let instance_metadata = client.get().expect("Couldn't get the instance metadata.");
/// ````
#[derive(Debug, Default)]
pub struct InstanceMetadataClient;

impl InstanceMetadataClient {
    const REQUEST_TIMEOUT_MS: u64 = 2000; // 2 seconds

    pub fn new() -> Self {
        Self {}
    }

    fn get_token(&self) -> Result<String> {
        const TOKEN_API_URL: &str = "http://169.254.169.254/latest/api/token";

        let resp = ureq::put(TOKEN_API_URL)
            .set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            .timeout_connect(Self::REQUEST_TIMEOUT_MS)
            .call();

        let token = resp.into_string()?;
        Ok(token)
    }

    /// Get the instance metadata for the machine.
    pub fn get(&self) -> Result<InstanceMetadata> {
        let token = self.get_token()?;
        let instance_id_resp = ureq::get(MetadataUrls::InstanceId.into())
            .set("X-aws-ec2-metadata-token", &token)
            .timeout_connect(Self::REQUEST_TIMEOUT_MS)
            .call();

        let instance_id = if instance_id_resp.ok() {
            instance_id_resp.into_string()?
        } else {
            return Err(Error::NotFound(MetadataUrls::InstanceId.into()));
        };

        let ident_creds_resp = ureq::get(MetadataUrls::AccountId.into())
            .set("X-aws-ec2-metadata-token", &token)
            .timeout_connect(Self::REQUEST_TIMEOUT_MS)
            .call();

        let account_id = if ident_creds_resp.ok() {
            let ident_creds = ident_creds_resp.into_string()?;
            identity_credentials_to_account_id(&ident_creds)?
        } else {
            return Err(Error::NotFound(MetadataUrls::AccountId.into()));
        };

        let ami_id_resp = ureq::get(MetadataUrls::AmiId.into())
            .set("X-aws-ec2-metadata-token", &token)
            .timeout_connect(Self::REQUEST_TIMEOUT_MS)
            .call();

        let ami_id = if ami_id_resp.ok() {
            ami_id_resp.into_string()?
        } else {
            return Err(Error::NotFound(MetadataUrls::AmiId.into()));
        };

        let availability_zone_resp = ureq::get(MetadataUrls::AvailabilityZone.into())
            .set("X-aws-ec2-metadata-token", &token)
            .timeout_connect(Self::REQUEST_TIMEOUT_MS)
            .call();

        let (availability_zone, region) = if availability_zone_resp.ok() {
            let availability_zone = availability_zone_resp.into_string()?;
            let region = availability_zone_to_region(&availability_zone)?;
            (availability_zone, region)
        } else {
            return Err(Error::NotFound(MetadataUrls::AvailabilityZone.into()));
        };

        let instance_type_resp = ureq::get(MetadataUrls::InstanceType.into())
            .set("X-aws-ec2-metadata-token", &token)
            .timeout_connect(Self::REQUEST_TIMEOUT_MS)
            .call();

        let instance_type = if instance_type_resp.ok() {
            instance_type_resp.into_string()?
        } else {
            return Err(Error::NotFound(MetadataUrls::InstanceType.into()));
        };

        let hostname_resp = ureq::get(MetadataUrls::Hostname.into())
            .set("X-aws-ec2-metadata-token", &token)
            .timeout_connect(Self::REQUEST_TIMEOUT_MS)
            .call();

        let hostname = if hostname_resp.ok() {
            hostname_resp.into_string()?
        } else {
            return Err(Error::NotFound(MetadataUrls::Hostname.into()));
        };

        let local_hostname_resp = ureq::get(MetadataUrls::LocalHostname.into())
            .set("X-aws-ec2-metadata-token", &token)
            .timeout_connect(Self::REQUEST_TIMEOUT_MS)
            .call();

        let local_hostname = if local_hostname_resp.ok() {
            local_hostname_resp.into_string()?
        } else {
            return Err(Error::NotFound(MetadataUrls::LocalHostname.into()));
        };

        let public_hostname_resp = ureq::get(MetadataUrls::PublicHostname.into())
            .set("X-aws-ec2-metadata-token", &token)
            .timeout_connect(Self::REQUEST_TIMEOUT_MS)
            .call();

        // "public-hostname" isn't always available - the instance must be configured
        // to support having one assigned.
        let public_hostname = if public_hostname_resp.ok() {
            Some(public_hostname_resp.into_string()?)
        } else {
            None
        };

        let spot_instance_action_resp = ureq::get(MetadataUrls::SpotInstanceAction.into())
            .set("X-aws-ec2-metadata-token", &token)
            .timeout_connect(Self::REQUEST_TIMEOUT_MS)
            .call();

        // "public-hostname" isn't always available - the instance must be configured
        // to support having one assigned.
        let spot_instance_action = if spot_instance_action_resp.ok() {
            let as_string = spot_instance_action_resp.into_string()?;
            Some(SpotInstanceAction::from_json_string(&as_string)?)
        } else {
            None
        };

        let metadata = InstanceMetadata {
            region,
            availability_zone,
            instance_id,
            account_id,
            ami_id,
            instance_type,
            hostname,
            local_hostname,
            public_hostname,
            spot_instance_action,
        };

        Ok(metadata)
    }
}

/// `InstanceMetadata` holds the fetched instance metadata. Fields
/// on this struct may be incomplete if AWS has updated the fields
/// or if they haven't been explicitly provided.
#[derive(Debug, Clone)]
pub struct InstanceMetadata {
    /// AWS Region - always available
    pub region: &'static str,

    /// AWS Availability Zone - always available
    pub availability_zone: String,

    /// AWS Instance Id - always available
    pub instance_id: String,

    /// AWS Account Id - always available, marked as Internal Only per:
    /// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html
    pub account_id: String,

    /// AWS AMS Id - always available
    pub ami_id: String,

    /// AWS Instance Type - always available
    pub instance_type: String,

    /// AWS Instance Local Hostname - always available
    pub local_hostname: String,

    /// AWS Instance Hostname - always available
    pub hostname: String,

    /// AWS Instance Public Hostname - optionally available
    pub public_hostname: Option<String>,

    /// AWS Spot Instance Action - optionally available if spot instance is marked to be stopped or
    /// terminated
    pub spot_instance_action: Option<SpotInstanceAction>,
}

impl std::fmt::Display for InstanceMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// `SpotInstanceAction` holds the spot instance action.
/// See: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-interruptions.html#instance-action-metadata
#[derive(Debug, Clone)]
pub struct SpotInstanceAction {
    /// The action
    pub action: String,

    /// The time for the action
    pub time: String,
}

impl SpotInstanceAction {
    fn from_json_string(json_str: &str) -> Result<SpotInstanceAction> {
        let parsed = json::parse(json_str)?;
        Ok(SpotInstanceAction {
            action: parsed["action"].to_string(),
            time: parsed["time"].to_string(),
        })
    }
}
