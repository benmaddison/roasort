use std::{cmp::Ordering, collections::BTreeMap, fmt, str::FromStr};

use anyhow::Context;

use ip::{
    any,
    concrete::{self, Prefix, PrefixLength},
    Afi, Ipv4, Ipv6,
};

use rasn::der;

use rasn_cms::{SignedData, CONTENT_SIGNED_DATA};

use crate::econtent::{RoaContentInfo, RouteOriginAttestation, ID_CT_ROUTE_ORIGIN_AUTHZ};

#[derive(Debug, Copy, Clone)]
enum MaxLength<A: Afi> {
    ImplicitEqual,
    ExplicitEqual,
    Explicit(PrefixLength<A>),
}

impl<A: Afi> PartialEq for MaxLength<A> {
    fn eq(&self, other: &Self) -> bool {
        matches!(self.cmp(other), Ordering::Equal)
    }
}

impl<A: Afi> Eq for MaxLength<A> {}

impl<A: Afi> PartialOrd for MaxLength<A> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<A: Afi> Ord for MaxLength<A> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (
                Self::ImplicitEqual | Self::ExplicitEqual,
                Self::ImplicitEqual | Self::ExplicitEqual,
            ) => Ordering::Equal,
            (Self::ImplicitEqual | Self::ExplicitEqual, Self::Explicit(_)) => Ordering::Less,
            (Self::Explicit(_), Self::ImplicitEqual | Self::ExplicitEqual) => Ordering::Greater,
            (Self::Explicit(p), Self::Explicit(q)) => p.cmp(q),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct InnerRoaPrefixRange<A: Afi> {
    prefix: Prefix<A>,
    max_length: MaxLength<A>,
}

impl<A: Afi> InnerRoaPrefixRange<A> {
    fn new(prefix: Prefix<A>, max_length: Option<PrefixLength<A>>) -> anyhow::Result<Self> {
        if let Some(max_length) = max_length {
            match max_length.cmp(&prefix.length()) {
                Ordering::Less => {
                    anyhow::bail!(
                        "got max_length ({max_length}) less than prefix length ({prefix})"
                    )
                }
                Ordering::Equal => Ok(Self {
                    prefix,
                    max_length: MaxLength::ExplicitEqual,
                }),
                Ordering::Greater => Ok(Self {
                    prefix,
                    max_length: MaxLength::Explicit(max_length),
                }),
            }
        } else {
            Ok(Self {
                prefix,
                max_length: MaxLength::ImplicitEqual,
            })
        }
    }
}

impl<A: Afi> PartialOrd for InnerRoaPrefixRange<A> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<A: Afi> Ord for InnerRoaPrefixRange<A> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.prefix.prefix().cmp(&other.prefix.prefix()) {
            Ordering::Equal => match self.prefix.length().cmp(&other.prefix.length()) {
                Ordering::Equal => self.max_length.cmp(&other.max_length),
                ord => ord,
            },
            ord => ord,
        }
    }
}

impl<A: Afi> fmt::Display for InnerRoaPrefixRange<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let MaxLength::Explicit(max_length) = self.max_length {
            write!(f, "{}-{}", self.prefix, max_length)
        } else {
            self.prefix.fmt(f)
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum RoaPrefixRange {
    Ipv4(InnerRoaPrefixRange<Ipv4>),
    Ipv6(InnerRoaPrefixRange<Ipv6>),
}

impl RoaPrefixRange {
    pub(crate) const fn has_explicit_equal_max_length(&self) -> bool {
        match self {
            Self::Ipv4(inner) => matches!(inner.max_length, MaxLength::ExplicitEqual),
            Self::Ipv6(inner) => matches!(inner.max_length, MaxLength::ExplicitEqual),
        }
    }
}

impl Ord for RoaPrefixRange {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Ipv4(i), Self::Ipv4(j)) => i.cmp(j),
            (Self::Ipv4(_), Self::Ipv6(_)) => Ordering::Less,
            (Self::Ipv6(_), Self::Ipv4(_)) => Ordering::Greater,
            (Self::Ipv6(i), Self::Ipv6(j)) => i.cmp(j),
        }
    }
}

impl PartialOrd for RoaPrefixRange {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl FromStr for RoaPrefixRange {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (raw_prefix, raw_len) = if let Some((p, l)) = input.split_once('-') {
            (p, Some(l))
        } else {
            (input, None)
        };
        match raw_prefix.parse::<any::Prefix>()? {
            any::Prefix::Ipv4(prefix) => {
                let max_length = raw_len
                    .map(|l| {
                        PrefixLength::<Ipv4>::from_primitive(l.parse()?)
                            .context("failed to parse max_length")
                    })
                    .transpose()?;
                InnerRoaPrefixRange::new(prefix, max_length).map(Self::Ipv4)
            }
            any::Prefix::Ipv6(prefix) => {
                let max_length = raw_len
                    .map(|l| {
                        PrefixLength::<Ipv6>::from_primitive(l.parse()?)
                            .context("failed to parse max_length")
                    })
                    .transpose()?;
                InnerRoaPrefixRange::new(prefix, max_length).map(Self::Ipv6)
            }
        }
    }
}

impl fmt::Display for RoaPrefixRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv4(inner) => inner.fmt(f),
            Self::Ipv6(inner) => inner.fmt(f),
        }
    }
}

pub(crate) struct RoaPrefixRanges(BTreeMap<RoaPrefixRange, usize>);

impl RoaPrefixRanges {
    pub(crate) fn from_text<S, I, E>(iter: I) -> anyhow::Result<Self>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = Result<S, E>>,
        E: std::error::Error + Send + Sync + 'static,
    {
        iter.into_iter()
            .map(|line| line.context("failed to get input line")?.as_ref().parse())
            .collect()
    }

    pub(crate) fn from_roa(bytes: &[u8]) -> anyhow::Result<Self> {
        log::info!("trying to decode ROA from input bytes");
        der::decode::<RoaContentInfo>(bytes)
            .context("failed to decode ContentInfo")?
            .try_into()
    }
}

impl FromIterator<RoaPrefixRange> for RoaPrefixRanges {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = RoaPrefixRange>,
    {
        let inner = iter
            .into_iter()
            .enumerate()
            .map(|(i, item)| (item, i))
            .collect();
        Self(inner)
    }
}

impl IntoIterator for RoaPrefixRanges {
    type Item = (RoaPrefixRange, usize);
    type IntoIter = <BTreeMap<RoaPrefixRange, usize> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl TryFrom<RoaContentInfo> for RoaPrefixRanges {
    type Error = anyhow::Error;

    fn try_from(value: RoaContentInfo) -> Result<Self, Self::Error> {
        log::info!("checking for id-ct-SignedData content-type");
        if CONTENT_SIGNED_DATA != value.content_type {
            let msg = "invalid OID for SignedData content";
            log::error!("{msg}");
            anyhow::bail!(msg);
        }
        log::info!("trying to decode content as SignedData");
        let content = value.content.as_bytes();
        let signed_data: SignedData =
            der::decode(content).context("failed to decode CMS content")?;

        let encap_content_info = signed_data.encap_content_info;
        if ID_CT_ROUTE_ORIGIN_AUTHZ != encap_content_info.content_type {
            anyhow::bail!("invalid OID for ROA eContent");
        }
        log::info!("trying to decode econtent as RouteOriginAttestation");
        let roa_econtent: RouteOriginAttestation = encap_content_info
            .content
            .ok_or_else(|| anyhow::anyhow!("failed to extract eContent bytes"))
            .and_then(|bytes| der::decode(bytes.as_ref()).context("failed to decode eContent"))?;

        roa_econtent
            .ip_addr_blocks()
            .flat_map(|roa_ip_addr_family| {
                let afi = roa_ip_addr_family.address_family();
                roa_ip_addr_family
                    .addresses()
                    .map(move |roa_ip_addr| match &afi {
                        Ok(concrete::Afi::Ipv4) => {
                            Ok(RoaPrefixRange::Ipv4(InnerRoaPrefixRange::new(
                                roa_ip_addr.address()?,
                                roa_ip_addr.max_length::<Ipv4>()?,
                            )?))
                        }
                        Ok(concrete::Afi::Ipv6) => {
                            Ok(RoaPrefixRange::Ipv6(InnerRoaPrefixRange::new(
                                roa_ip_addr.address()?,
                                roa_ip_addr.max_length::<Ipv6>()?,
                            )?))
                        }
                        Err(_) => anyhow::bail!("invalid IP address family indicator"),
                    })
            })
            .collect::<Result<_, _>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_from_text() -> anyhow::Result<()> {
        let input = vec![
            Ok::<_, std::io::Error>("10.0.0.0/24"),
            Ok("10.0.0.0/24-24"),
            Ok("10.0.0.0/8"),
            Ok("2001:db8:db8::/48"),
            Ok("2001:db8::/32"),
        ];
        let expect = vec![
            "10.0.0.0/8",
            "10.0.0.0/24",
            "2001:db8::/32",
            "2001:db8:db8::/48",
        ];
        let mut errs = 0usize;
        let output: Vec<_> = RoaPrefixRanges::from_text(input)?
            .into_iter()
            .enumerate()
            .map(|(i, (item, j))| {
                if i != j {
                    errs += 1;
                };
                if item.has_explicit_equal_max_length() {
                    errs += 1;
                }
                item.to_string()
            })
            .collect();
        assert_eq!(output, expect);
        assert_eq!(errs, 3);
        Ok(())
    }

    assert_relations! {
        ipv4_eq: "10.0.0.0/8" == "10.0.0.0/8-8";
        ipv4_ne: "192.168.0.0/24" != "192.168.0.0/24-26";
        ipv4_lt_ipv6: "10.0.0.0/8" < "2001:db8::/32";
        low_lt_high: "10.0.0.0/8-10" < "11.0.0.0/8-10";
        short_lt_long: "10.0.0.0/8-10" < "10.0.0.0/9";
        lowmax_lt_highmax: "10.0.0.0/8-10" < "10.0.0.0/8-12";
    }

    macro_rules! assert_relations {
        ( $( $label:ident : $lhs:literal $op:tt $rhs:literal );* $(;)? ) => {
            $(
                #[test]
                fn $label() {
                    let lhs = $lhs.parse::<RoaPrefixRange>().unwrap();
                    let rhs = $rhs.parse::<RoaPrefixRange>().unwrap();
                    assert!(lhs $op rhs);
                }
            )*
        };
    }
    use assert_relations;
}
