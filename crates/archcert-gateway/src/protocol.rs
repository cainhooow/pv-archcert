use crate::IngressError;
use archcert_domain::{GitObjectId, source::SourcePath};
use archcert_source::GitObjectFormat;
use gix_packetline::{
    PacketLineRef,
    decode::{self, PacketLineOrWantedSize},
};
use std::io::Read;

pub(crate) fn valid_route(route: &str) -> bool {
    route
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        && route.len() <= 256
        && route.ends_with(".git")
        && SourcePath::from_bytes(route.as_bytes()).is_ok()
        && !route.contains('\'')
}
pub(crate) fn receive_route(original: &str) -> Result<&str, IngressError> {
    if original.len() > 300 {
        return Err(IngressError::Command);
    }
    let route = original
        .strip_prefix("git-receive-pack '")
        .and_then(|s| s.strip_suffix('\''))
        .ok_or(IngressError::Command)?;
    if !valid_route(route) {
        return Err(IngressError::Command);
    }
    Ok(route)
}
pub(crate) struct ReceiveCommand {
    pub reference: String,
    pub commit: GitObjectId,
    pub raw: Vec<u8>,
}
fn packet(input: &mut impl Read) -> Result<Vec<u8>, IngressError> {
    let mut prefix = [0; 4];
    input
        .read_exact(&mut prefix)
        .map_err(|_| IngressError::Rejected)?;
    let wanted = match decode::hex_prefix(&prefix).map_err(|_| IngressError::Rejected)? {
        PacketLineOrWantedSize::Line(PacketLineRef::Flush) => 0,
        PacketLineOrWantedSize::Line(_) => return Err(IngressError::Rejected),
        PacketLineOrWantedSize::Wanted(n) => usize::from(n),
    };
    if wanted > 4096 {
        return Err(IngressError::Limit);
    }
    let mut bytes = prefix.to_vec();
    bytes.resize(wanted + 4, 0);
    input
        .read_exact(&mut bytes[4..])
        .map_err(|_| IngressError::Rejected)?;
    Ok(bytes)
}
pub(crate) fn read_command(
    input: &mut impl Read,
    format: GitObjectFormat,
) -> Result<ReceiveCommand, IngressError> {
    let first = packet(input)?;
    let mut raw = Vec::new();
    let shallow = match decode::all_at_once(&first).map_err(|_| IngressError::Rejected)? {
        PacketLineRef::Data(bytes) if bytes.starts_with(b"shallow ") => {
            let oid = std::str::from_utf8(&bytes[8..])
                .map_err(|_| IngressError::Rejected)?
                .trim_end_matches('\n');
            if oid.len() != format.width()
                || !oid
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(IngressError::Rejected);
            }
            let oid = oid.to_owned();
            raw.extend_from_slice(&first);
            Some(oid)
        }
        _ => None,
    };
    let command_packet = if shallow.is_some() {
        packet(input)?
    } else {
        first
    };
    raw.extend_from_slice(&command_packet);
    let line = decode::all_at_once(&command_packet).map_err(|_| IngressError::Rejected)?;
    let PacketLineRef::Data(bytes) = line else {
        return Err(IngressError::Rejected);
    };
    let text = std::str::from_utf8(bytes)
        .map_err(|_| IngressError::Rejected)?
        .trim_end_matches('\n');
    let (update, capabilities) = text.split_once('\0').ok_or(IngressError::Rejected)?;
    for cap in capabilities.split(' ').filter(|c| !c.is_empty()) {
        if ![
            "report-status",
            "report-status-v2",
            "side-band-64k",
            "ofs-delta",
            "atomic",
            "quiet",
        ]
        .contains(&cap)
            && cap != format!("object-format={}", format.name())
            && !(cap.starts_with("agent=")
                && cap.len() <= 128
                && cap.bytes().all(|b| b.is_ascii_graphic()))
        {
            return Err(IngressError::Rejected);
        }
    }
    if !capabilities
        .split(' ')
        .any(|c| matches!(c, "report-status" | "report-status-v2"))
    {
        return Err(IngressError::Rejected);
    }
    let parts: Vec<_> = update.split(' ').collect();
    if parts.len() != 3
        || parts[0] != "0".repeat(format.width())
        || parts[1].len() != format.width()
        || !parts[1]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || parts[1].bytes().all(|b| b == b'0')
    {
        return Err(IngressError::Rejected);
    }
    let reference = parts[2];
    let branch = reference
        .strip_prefix("refs/heads/")
        .ok_or(IngressError::Rejected)?;
    if reference.len() > 256
        || SourcePath::from_bytes(branch.as_bytes()).is_err()
        || branch.contains("..")
        || branch.contains("@{")
        || branch
            .split('/')
            .any(|p| p.starts_with('.') || p.ends_with(".lock"))
    {
        return Err(IngressError::Rejected);
    }
    let commit = GitObjectId::parse(parts[1]).map_err(|_| IngressError::Rejected)?;
    if shallow.as_ref().is_some_and(|id| id != commit.as_str()) {
        return Err(IngressError::Rejected);
    }
    let reference = reference.to_owned();
    let flush = packet(input)?;
    if flush != b"0000" {
        return Err(IngressError::Rejected);
    }
    raw.extend_from_slice(&flush);
    Ok(ReceiveCommand {
        reference,
        commit,
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wire(update: &str) -> Vec<u8> {
        let line = format!("{update}\0report-status object-format=sha1");
        format!("{:04x}{line}0000", line.len() + 4).into_bytes()
    }
    #[test]
    fn rejects_ref_confusion_deletion_force_updates_and_multiple_refs() {
        let oid = "1".repeat(40);
        let zero = "0".repeat(40);
        let valid = format!("{zero} {oid} refs/heads/main");
        assert!(read_command(&mut wire(&valid).as_slice(), GitObjectFormat::Sha1).is_ok());
        for update in [
            format!("{oid} {oid} refs/heads/main"),
            format!("{zero} {zero} refs/heads/main"),
            format!("{zero} {oid} refs/tags/main"),
            format!("{zero} {oid} HEAD"),
            format!("{zero} {oid} refs/archcert/candidates/a"),
            format!("{zero} {oid} refs/heads/../main"),
            format!("{zero} {oid} refs/heads/.hidden"),
            format!("{zero} {oid} refs/heads/a.lock"),
        ] {
            assert!(read_command(&mut wire(&update).as_slice(), GitObjectFormat::Sha1).is_err());
        }
        let mut multiple = wire(&valid);
        multiple.truncate(multiple.len() - 4);
        multiple.extend_from_slice(&wire(&valid));
        assert!(read_command(&mut multiple.as_slice(), GitObjectFormat::Sha1).is_err());
    }
    #[test]
    fn original_command_never_enters_a_shell() {
        assert_eq!(
            receive_route("git-receive-pack 'company/project.git'").ok(),
            Some("company/project.git")
        );
        for command in [
            "",
            "sh",
            "scp -t x",
            "sftp",
            "git-upload-pack 'x.git'",
            "git-receive-pack '../x.git'",
            "git-receive-pack 'x.git'; id",
            "git-receive-pack '$(id).git'",
            "git-receive-pack 'x.git'\n",
        ] {
            assert!(receive_route(command).is_err(), "{command}");
        }
    }
}
