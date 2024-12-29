#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        _bindgen_ty_38 as BpfLookupRet, bpf_fib_lookup,
        bpf_fib_lookup__bindgen_ty_1 as FLTotLenMTU, bpf_fib_lookup__bindgen_ty_2 as FLTosFlow,
        bpf_fib_lookup__bindgen_ty_3 as FLIpSrc, bpf_fib_lookup__bindgen_ty_4 as FLIpDst,
        bpf_fib_lookup__bindgen_ty_5 as LFVlan, xdp_action, BPF_FIB_LKUP_RET_PROHIBIT,
        BPF_FIB_LKUP_RET_SUCCESS,
    },
    helpers::{bpf_fib_lookup, bpf_redirect},
    macros::xdp,
    programs::XdpContext,
    EbpfContext,
};

use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn urouter(ctx: XdpContext) -> u32 {
    match try_urouter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_urouter(ctx: XdpContext) -> Result<u32, ()> {
    info!(&ctx, "received a packet");

    let mut fibparams: bpf_fib_lookup;
    let family: u8;
    let l4_protocol: u8;
    let sport: u16;
    let dport: u16;
    let ifindex: u32 = unsafe { *ctx.ctx }.ingress_ifindex;
    let smac: [u8; 6] = [0; 6];
    let dmac: [u8; 6] = [0; 6];
    let totlen_mtu: FLTotLenMTU;
    let tos_flow: FLTosFlow;
    let src: FLIpSrc;
    let dst: FLIpDst;
    let vlan: LFVlan = LFVlan { tbid: 0 };

    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ip: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

            if unsafe { *ip }.ttl <= 1 {
                return Ok(xdp_action::XDP_PASS);
            }

            family = AF_INET;
            src = FLIpSrc {
                ipv4_src: unsafe { *ip }.src_addr,
            };
            dst = FLIpDst {
                ipv4_dst: unsafe { *ip }.dst_addr,
            };
            totlen_mtu = FLTotLenMTU {
                tot_len: u16::from_be(unsafe { *ip }.tot_len),
            };
            tos_flow = FLTosFlow {
                tos: unsafe { *ip }.tos,
            };
            match unsafe { (*ip).proto } {
                IpProto::Tcp => {
                    let hdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    l4_protocol = IpProto::Tcp as u8;
                    sport = u16::from_be(unsafe { *hdr }.source);
                    dport = u16::from_be(unsafe { *hdr }.dest);
                }
                IpProto::Udp => {
                    let hdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    l4_protocol = IpProto::Udp as u8;
                    sport = u16::from_be(unsafe { *hdr }.source);
                    dport = u16::from_be(unsafe { *hdr }.dest);
                }
                _ => return Ok(xdp_action::XDP_PASS),
            };
        }
        EtherType::Ipv6 => {
            let ip: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let flowinfo: *const u32 = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

            if unsafe { *ip }.hop_limit <= 1 {
                return Ok(xdp_action::XDP_PASS);
            }

            family = AF_INET6;
            src = FLIpSrc {
                ipv6_src: unsafe { (*ip).src_addr.in6_u.u6_addr32 },
            };
            dst = FLIpDst {
                ipv6_dst: unsafe { (*ip).dst_addr.in6_u.u6_addr32 },
            };
            totlen_mtu = FLTotLenMTU {
                tot_len: u16::from_be(unsafe { *ip }.payload_len),
            };
            tos_flow = FLTosFlow {
                flowinfo: unsafe { *flowinfo } & 0x0FFFFFFF,
            };
            match unsafe { (*ip).next_hdr } {
                IpProto::Tcp => {
                    let hdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;
                    l4_protocol = IpProto::Tcp as u8;
                    sport = u16::from_be(unsafe { *hdr }.source);
                    dport = u16::from_be(unsafe { *hdr }.dest);
                }
                IpProto::Udp => {
                    let hdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;
                    l4_protocol = IpProto::Udp as u8;
                    sport = u16::from_be(unsafe { *hdr }.source);
                    dport = u16::from_be(unsafe { *hdr }.dest);
                }
                _ => return Ok(xdp_action::XDP_PASS),
            };
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    fibparams = bpf_fib_lookup {
        family,
        l4_protocol,
        sport,
        dport,
        __bindgen_anon_1: totlen_mtu,
        ifindex,
        __bindgen_anon_2: tos_flow,
        __bindgen_anon_3: src,
        __bindgen_anon_4: dst,
        __bindgen_anon_5: vlan,
        smac,
        dmac,
    };

    let ret: BpfLookupRet;
    unsafe {
        ret = bpf_fib_lookup(
            ctx.as_ptr(),
            &mut fibparams,
            mem::size_of_val(&fibparams).try_into().unwrap(),
            0,
        )
        .try_into()
        .unwrap();
    };

    match ret {
        BPF_FIB_LKUP_RET_SUCCESS => {
            match unsafe { (*ethhdr).ether_type } {
                EtherType::Ipv4 => {
                    let ip: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
                    let ip: *mut Ipv4Hdr = ip as *mut Ipv4Hdr;
                    unsafe { decrease_ttl(ip) };
                }
                EtherType::Ipv6 => {
                    let ip: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
                    let ip: *mut Ipv6Hdr = ip as *mut Ipv6Hdr;
                    unsafe { *ip }.hop_limit -= 1;
                }
                _ => return Ok(xdp_action::XDP_PASS),
            }
            let eth: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
            let eth: *mut EthHdr = eth as *mut EthHdr;
            unsafe { *eth }.src_addr = fibparams.smac;
            unsafe { *eth }.dst_addr = fibparams.dmac;
            return Ok(unsafe { bpf_redirect(fibparams.ifindex, 0) }
                .try_into()
                .unwrap());
        }
        BPF_FIB_LKUP_RET_PROHIBIT => return Ok(xdp_action::XDP_DROP),
        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline]
pub unsafe fn decrease_ttl(ip: *mut Ipv4Hdr) -> u16 {
    let mut csum: u64 = !(*ip).check as u64;
    let old: u16 = (((*ip).ttl as u16) << 8) + (*ip).proto as u16;
    (*ip).ttl -= 1;
    let new: u16 = (((*ip).ttl as u16) << 8) + (*ip).proto as u16;
    csum -= old as u64;
    csum = (csum & 0xffff) + (csum >> 16);
    csum += new as u64;
    csum = (csum & 0xffff) + (csum >> 16);
    (*ip).check = !(csum as u16);
    !(csum as u16)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
