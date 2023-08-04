use anyhow::Context;

use ip::{
    concrete::{self, Address, Prefix},
    traits::Afi,
    PrefixLength,
};

use num_traits::cast::ToPrimitive;

use rasn::{
    types::{BitString, Integer, OctetString, Oid, SequenceOf},
    AsnType, Decode, Encode,
};

use rasn_cms::ContentInfo;

pub(crate) const ID_CT_ROUTE_ORIGIN_AUTHZ: &Oid =
    Oid::const_new(&[1, 2, 840, 113_549, 1, 9, 16, 1, 24]);

pub(crate) type RoaContentInfo = ContentInfo;

#[derive(Debug, Clone, AsnType, Encode, Decode)]
pub(crate) struct RouteOriginAttestation {
    #[rasn(tag(explicit(0)), default(0))]
    version: Integer,
    as_id: AsId,
    #[rasn(size("1..=2"))]
    ip_addr_blocks: SequenceOf<RoaIpAddressFamily>,
}

impl RouteOriginAttestation {
    pub(crate) fn ip_addr_blocks(self) -> impl Iterator<Item = RoaIpAddressFamily> {
        self.ip_addr_blocks.into_iter()
    }
}

#[derive(Debug, Clone, AsnType, Encode, Decode)]
#[rasn(delegate, value("0..=4294967295"))]
struct AsId(Integer);

#[derive(Debug, Clone, AsnType, Encode, Decode)]
pub(crate) struct RoaIpAddressFamily {
    #[rasn(size(2))]
    address_family: OctetString,
    #[rasn(size("1.."))]
    addresses: SequenceOf<RoaIpAddress>,
}

impl RoaIpAddressFamily {
    pub(crate) fn address_family(&self) -> anyhow::Result<concrete::Afi> {
        log::info!("trying to get address-family");
        match self.address_family.as_ref() {
            &[0, 1] => Ok(concrete::Afi::Ipv4),
            &[0, 2] => Ok(concrete::Afi::Ipv6),
            x => anyhow::bail!("invalid address-family '{x:?}'"),
        }
    }

    pub(crate) fn addresses(self) -> impl Iterator<Item = RoaIpAddress> {
        self.addresses.into_iter()
    }
}

#[derive(Debug, Clone, AsnType, Encode, Decode)]
pub(crate) struct RoaIpAddress {
    #[rasn(size("0..=128"))]
    address: BitString,
    #[rasn(value("0..=128"))]
    max_length: Option<Integer>,
}

impl RoaIpAddress {
    pub(crate) fn address<A: Afi>(&self) -> anyhow::Result<Prefix<A>> {
        log::info!("trying to read IP prefix bits");
        let address = Address::from_slice(self.address.as_raw_slice())
            .context("failed to read IP address from bit string")?;
        log::info!("trying to get IP prefix length");
        let length = self.address.len().try_into()?;
        Ok(Prefix::new(address, length))
    }

    pub(crate) fn max_length<A: Afi>(&self) -> anyhow::Result<Option<PrefixLength<A>>> {
        self.max_length
            .as_ref()
            .map(|int| {
                int.to_usize()
                    .ok_or_else(|| {
                        anyhow::anyhow!("failed to convert max_length value '{int:?}' to usize")
                    })
                    .and_then(|l| l.try_into().context("failed to construct prefix-length"))
            })
            .transpose()
    }
}
