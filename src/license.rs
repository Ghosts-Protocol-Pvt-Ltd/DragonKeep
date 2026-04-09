//! DragonKeep license management — offline Ed25519-verified license system.
//!
//! License keys follow the format `DK-XXXX-XXXX-XXXX-XXXX` using a Base32
//! alphabet that excludes ambiguous characters (I, L, O, 1). Licenses are
//! signed with Ed25519 and verified offline against an embedded public key.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use ring::signature::{self, KeyPair};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

// ── Constants ────────────────────────────────────────────────────────────────

/// Base32 alphabet excluding ambiguous characters (I, L, O, 1).
const KEY_ALPHABET: &[u8; 32] = b"ABCDEFGHJKMNPQRSTUVWXYZ023456789";

/// License key prefix.
const KEY_PREFIX: &str = "DK";

/// Ed25519 public key for offline license verification.
/// This corresponds to the private key held by the license-issuing authority.
const PUBLIC_KEY_BYTES: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

// ── Feature sets ─────────────────────────────────────────────────────────────

/// Features available to all Community-tier (and above) licenses.
const COMMUNITY_FEATURES: &[&str] = &[
    "engine_sentinel",
    "engine_forge",
    "engine_warden",
    "engine_bastion",
    "engine_citadel",
    "engine_spectre",
    "engine_aegis",
    "engine_phantom",
    "engine_hydra",
    "engine_drake",
    "engine_talon",
    "cli_output",
    "export_json",
    "export_sarif",
];

/// Additional features unlocked by a Pro-tier license.
const PRO_FEATURES: &[&str] = &[
    "scheduled_scans",
    "historical_diffing",
    "compliance_templates",
    "email_reports",
];

/// Additional features unlocked by an Enterprise-tier license.
const ENTERPRISE_FEATURES: &[&str] = &[
    "web_dashboard",
    "multi_host",
    "api_access",
    "custom_compliance",
];

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("invalid license key format — expected DK-XXXX-XXXX-XXXX-XXXX")]
    InvalidKeyFormat,

    #[error("license signature verification failed")]
    InvalidSignature,

    #[error("license has expired (expired at {0})")]
    Expired(DateTime<Utc>),

    #[error("feature '{0}' requires a higher license tier")]
    FeatureNotAvailable(String),

    #[error("no license file found at {0}")]
    NotFound(PathBuf),

    #[error("failed to read license file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse license JSON: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("could not determine config directory")]
    NoConfigDir,
}

pub type LicenseResult<T> = Result<T, LicenseError>;

// ── Tier ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    Community,
    Pro,
    Enterprise,
}

impl std::fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Community => write!(f, "Community"),
            Self::Pro => write!(f, "Pro"),
            Self::Enterprise => write!(f, "Enterprise"),
        }
    }
}

// ── Data structures ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub key: String,
    pub tier: LicenseTier,
    pub issued_to: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_hosts: u32,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLicense {
    pub license: License,
    /// Base64-encoded Ed25519 signature over the canonical JSON of `license`.
    pub signature: String,
}

// ── Key validation ───────────────────────────────────────────────────────────

/// Validate the format of a license key: `DK-XXXX-XXXX-XXXX-XXXX`.
pub fn validate_key_format(key: &str) -> bool {
    let parts: Vec<&str> = key.split('-').collect();
    if parts.len() != 5 || parts[0] != KEY_PREFIX {
        return false;
    }
    parts[1..].iter().all(|segment| {
        segment.len() == 4 && segment.bytes().all(|b| KEY_ALPHABET.contains(&b))
    })
}

/// Generate a cryptographically random license key.
pub fn generate_license_key() -> String {
    use ring::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).expect("system RNG failed");

    let chars: Vec<char> = bytes
        .iter()
        .map(|&b| KEY_ALPHABET[(b & 0x1F) as usize] as char)
        .collect();

    format!(
        "{KEY_PREFIX}-{}-{}-{}-{}",
        chars[0..4].iter().collect::<String>(),
        chars[4..8].iter().collect::<String>(),
        chars[8..12].iter().collect::<String>(),
        chars[12..16].iter().collect::<String>(),
    )
}

// ── Paths ────────────────────────────────────────────────────────────────────

/// Return the path to the license file: `~/.config/dragonkeep/license.json`.
pub fn license_path() -> LicenseResult<PathBuf> {
    let config = dirs::config_dir().ok_or(LicenseError::NoConfigDir)?;
    Ok(config.join("dragonkeep").join("license.json"))
}

// ── Keypair utilities (for the license-issuing authority) ────────────────────

/// Generate a new Ed25519 keypair.
///
/// Returns `(pkcs8_private_key, public_key_bytes)`. The public key bytes should
/// be embedded in the binary as `PUBLIC_KEY_BYTES` for offline verification.
pub fn generate_keypair() -> LicenseResult<(Vec<u8>, Vec<u8>)> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| LicenseError::InvalidSignature)?;
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| LicenseError::InvalidSignature)?;
    let public_key = key_pair.public_key().as_ref().to_vec();
    Ok((pkcs8.as_ref().to_vec(), public_key))
}

/// Sign a license with an Ed25519 private key in PKCS#8 DER format.
///
/// Used by the license-issuing server — not by the client binary.
pub fn sign_license(license: &License, pkcs8_private_key: &[u8]) -> LicenseResult<SignedLicense> {
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_private_key)
        .map_err(|_| LicenseError::InvalidSignature)?;
    let canonical = serde_json::to_string(license)?;
    let sig = key_pair.sign(canonical.as_bytes());

    Ok(SignedLicense {
        license: license.clone(),
        signature: BASE64.encode(sig.as_ref()),
    })
}

// ── Core verification ────────────────────────────────────────────────────────

/// Verify the Ed25519 signature of a [`SignedLicense`] using the embedded
/// public key. Returns the inner [`License`] on success.
pub fn verify_license(signed: &SignedLicense) -> LicenseResult<&License> {
    if !validate_key_format(&signed.license.key) {
        return Err(LicenseError::InvalidKeyFormat);
    }

    // Canonical JSON of the license payload
    let canonical =
        serde_json::to_string(&signed.license).map_err(|_| LicenseError::InvalidSignature)?;

    // Decode the base64 signature
    let sig_bytes = BASE64
        .decode(&signed.signature)
        .map_err(|_| LicenseError::InvalidSignature)?;

    // Verify against the embedded public key
    let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &PUBLIC_KEY_BYTES);
    public_key
        .verify(canonical.as_bytes(), &sig_bytes)
        .map_err(|_| LicenseError::InvalidSignature)?;

    // Check expiration
    if signed.license.expires_at < Utc::now() {
        return Err(LicenseError::Expired(signed.license.expires_at));
    }

    Ok(&signed.license)
}

// ── Load / activate ──────────────────────────────────────────────────────────

/// Load a [`SignedLicense`] from `~/.config/dragonkeep/license.json`.
pub fn load_license() -> LicenseResult<SignedLicense> {
    let path = license_path()?;
    if !path.exists() {
        return Err(LicenseError::NotFound(path));
    }
    let contents = fs::read_to_string(&path)?;
    let signed: SignedLicense = serde_json::from_str(&contents)?;
    Ok(signed)
}

/// Parse, verify, and persist a license from its JSON representation.
///
/// The license is verified before being saved to disk. The file is written
/// with restrictive permissions (0o600 on Unix).
pub fn activate_license(json_str: &str) -> LicenseResult<SignedLicense> {
    let signed: SignedLicense = serde_json::from_str(json_str)?;
    verify_license(&signed)?;

    let path = license_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&path, json_str)?;
    set_restrictive_permissions(&path)?;

    Ok(signed)
}

/// Set file permissions to 0o600 on Unix (owner read/write only).
#[cfg(unix)]
fn set_restrictive_permissions(path: &std::path::Path) -> LicenseResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_restrictive_permissions(_path: &std::path::Path) -> LicenseResult<()> {
    Ok(())
}

// ── Tier / feature queries ───────────────────────────────────────────────────

/// Return the current license tier, defaulting to [`LicenseTier::Community`]
/// if no valid license is found.
pub fn get_tier() -> LicenseTier {
    load_license()
        .ok()
        .and_then(|signed| verify_license(&signed).ok().map(|l| l.tier))
        .unwrap_or(LicenseTier::Community)
}

/// Check whether the current license grants access to a specific feature.
///
/// Falls back to Community-tier features if no valid license is loaded.
pub fn has_feature(feature: &str) -> bool {
    let (tier, extra_features) = match load_license() {
        Ok(ref signed) => match verify_license(signed) {
            Ok(license) => (license.tier, license.features.clone()),
            Err(_) => (LicenseTier::Community, Vec::new()),
        },
        Err(_) => (LicenseTier::Community, Vec::new()),
    };

    tier_has_feature(tier, feature) || extra_features.iter().any(|f| f == feature)
}

/// Check whether a tier's built-in feature set includes the given feature.
pub fn tier_has_feature(tier: LicenseTier, feature: &str) -> bool {
    let check = |set: &[&str]| set.iter().any(|&f| f == feature);

    match tier {
        LicenseTier::Community => check(COMMUNITY_FEATURES),
        LicenseTier::Pro => check(COMMUNITY_FEATURES) || check(PRO_FEATURES),
        LicenseTier::Enterprise => {
            check(COMMUNITY_FEATURES) || check(PRO_FEATURES) || check(ENTERPRISE_FEATURES)
        }
    }
}

/// Return the full list of features available for a given tier.
pub fn features_for_tier(tier: LicenseTier) -> Vec<&'static str> {
    let mut features: Vec<&'static str> = COMMUNITY_FEATURES.to_vec();
    if tier >= LicenseTier::Pro {
        features.extend_from_slice(PRO_FEATURES);
    }
    if tier >= LicenseTier::Enterprise {
        features.extend_from_slice(ENTERPRISE_FEATURES);
    }
    features
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_key_format() {
        assert!(validate_key_format("DK-ABCD-EFGH-JKMN-PQ23"));
        assert!(validate_key_format("DK-0234-5678-9ABC-DEFG"));
    }

    #[test]
    fn invalid_key_formats() {
        assert!(!validate_key_format("XX-ABCD-EFGH-JKMN-PQ23")); // wrong prefix
        assert!(!validate_key_format("DK-ABCD-EFGH-JKMN"));       // too few segments
        assert!(!validate_key_format("DK-ABC-EFGH-JKMN-PQ23"));   // segment too short
        assert!(!validate_key_format("DK-ABCI-EFGH-JKMN-PQ23"));  // ambiguous char I
        assert!(!validate_key_format("DK-ABCL-EFGH-JKMN-PQ23"));  // ambiguous char L
        assert!(!validate_key_format("DK-ABCO-EFGH-JKMN-PQ23"));  // ambiguous char O
        assert!(!validate_key_format("DK-ABC1-EFGH-JKMN-PQ23"));  // ambiguous char 1
    }

    #[test]
    fn generated_key_is_valid() {
        let key = generate_license_key();
        assert!(validate_key_format(&key), "generated key should be valid: {key}");
    }

    #[test]
    fn community_features_available() {
        assert!(tier_has_feature(LicenseTier::Community, "engine_sentinel"));
        assert!(tier_has_feature(LicenseTier::Community, "export_json"));
        assert!(!tier_has_feature(LicenseTier::Community, "scheduled_scans"));
    }

    #[test]
    fn pro_includes_community() {
        assert!(tier_has_feature(LicenseTier::Pro, "engine_sentinel"));
        assert!(tier_has_feature(LicenseTier::Pro, "scheduled_scans"));
        assert!(!tier_has_feature(LicenseTier::Pro, "web_dashboard"));
    }

    #[test]
    fn enterprise_includes_all() {
        assert!(tier_has_feature(LicenseTier::Enterprise, "engine_sentinel"));
        assert!(tier_has_feature(LicenseTier::Enterprise, "scheduled_scans"));
        assert!(tier_has_feature(LicenseTier::Enterprise, "web_dashboard"));
    }

    #[test]
    fn features_for_tier_counts() {
        assert_eq!(features_for_tier(LicenseTier::Community).len(), 14);
        assert_eq!(features_for_tier(LicenseTier::Pro).len(), 18);
        assert_eq!(features_for_tier(LicenseTier::Enterprise).len(), 22);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (pkcs8, _pub_key) = generate_keypair().unwrap();

        let license = License {
            key: generate_license_key(),
            tier: LicenseTier::Pro,
            issued_to: "test@example.com".into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(365),
            max_hosts: 5,
            features: vec!["custom_addon".into()],
        };

        // Sign with the generated private key
        let signed = sign_license(&license, &pkcs8).unwrap();

        // Verification against the *embedded* public key will fail because the
        // generated keypair differs from PUBLIC_KEY_BYTES — this is expected.
        // In production, PUBLIC_KEY_BYTES would match the issuing keypair.
        assert!(verify_license(&signed).is_err());

        // But the signature bytes are valid Ed25519 (verify with the matching key)
        let public_key =
            signature::UnparsedPublicKey::new(&signature::ED25519, &_pub_key);
        let canonical = serde_json::to_string(&signed.license).unwrap();
        let sig_bytes = BASE64.decode(&signed.signature).unwrap();
        assert!(public_key.verify(canonical.as_bytes(), &sig_bytes).is_ok());
    }
}
