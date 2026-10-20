//! Public-only RFC 8032 interoperability and malformed key regression vectors.
use archcert_crypto::{DetachedSignature, PublicKey};
type R = Result<(), Box<dyn std::error::Error>>;
#[test]
fn rfc8032_empty_message_vector_verifies_without_a_private_key() -> R {
    let key =
        PublicKey::from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")?;
    let signature = DetachedSignature::from_hex(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ))?;
    key.verify(b"", &signature)?;
    assert!(key.verify(b"altered", &signature).is_err());
    Ok(())
}
#[test]
fn weak_noncanonical_wrong_length_and_nonhex_public_keys_reject() {
    for key in [
        "00".repeat(32),
        format!("01{}", "00".repeat(31)),
        "ff".repeat(32),
        "00".repeat(31),
        "gg".repeat(32),
        "D7".repeat(32),
    ] {
        assert!(PublicKey::from_hex(&key).is_err());
    }
}
