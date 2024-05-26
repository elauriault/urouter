#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        _bindgen_ty_38, bpf_fib_lookup, bpf_fib_lookup__bindgen_ty_1, bpf_fib_lookup__bindgen_ty_2,
        bpf_fib_lookup__bindgen_ty_3, bpf_fib_lookup__bindgen_ty_4, bpf_fib_lookup__bindgen_ty_5,
        xdp_action, BPF_FIB_LKUP_RET_PROHIBIT, BPF_FIB_LKUP_RET_SUCCESS,
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

type BpfLookupRet = _bindgen_ty_38;

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
    let mut l4_protocol: u8 = 0;
    let mut sport: u16 = 0;
    let mut dport: u16 = 0;
    let ifindex: u32 = 0;
    let smac: [u8; 6] = [0; 6];
    let dmac: [u8; 6] = [0; 6];
    let __bindgen_anon_1: bpf_fib_lookup__bindgen_ty_1 =
        bpf_fib_lookup__bindgen_ty_1 { tot_len: 0 };
    let __bindgen_anon_2: bpf_fib_lookup__bindgen_ty_2 = bpf_fib_lookup__bindgen_ty_2 { tos: 0 };
    let __bindgen_anon_3: bpf_fib_lookup__bindgen_ty_3 =
        bpf_fib_lookup__bindgen_ty_3 { ipv4_src: 0 };
    let __bindgen_anon_4: bpf_fib_lookup__bindgen_ty_4 =
        bpf_fib_lookup__bindgen_ty_4 { ipv4_dst: 0 };
    let __bindgen_anon_5: bpf_fib_lookup__bindgen_ty_5 = bpf_fib_lookup__bindgen_ty_5 { tbid: 0 };

    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ip: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            family = AF_INET;
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
                _ => {}
            };
        }
        EtherType::Ipv6 => {
            let ip: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            family = AF_INET6;
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
                _ => {}
            };
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    fibparams = bpf_fib_lookup {
        family,
        l4_protocol,
        sport,
        dport,
        __bindgen_anon_1,
        ifindex,
        __bindgen_anon_2,
        __bindgen_anon_3,
        __bindgen_anon_4,
        __bindgen_anon_5,
        smac,
        dmac,
    };

    let ret: BpfLookupRet;
    unsafe {
        ret = bpf_fib_lookup(
            ctx.as_ptr(),
            &mut fibparams,
            mem::size_of::<bpf_fib_lookup> as i32,
            0,
        )
        .try_into()
        .unwrap();
    };

    match ret {
        BPF_FIB_LKUP_RET_SUCCESS => {
            return Ok(unsafe { bpf_redirect(fibparams.ifindex, 0) }
                .try_into()
                .unwrap());
        }
        BPF_FIB_LKUP_RET_PROHIBIT => return Ok(xdp_action::XDP_DROP),
        _ => {}
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
