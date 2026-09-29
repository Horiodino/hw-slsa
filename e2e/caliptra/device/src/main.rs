// Licensed under the Apache-2.0 license
//
// The simulated Caliptra device used by the HSLSA end-to-end example.
//
//   hslsa-caliptra-device inspect --fw <bundle> --out <dir>
//       Split a signed firmware bundle into its FMC and runtime images and
//       write the values a programming station burns into fuses.
//   hslsa-caliptra-device csr --rom <rom> --fuses <unit.json> --out <dir>
//       Boot in the Manufacturing lifecycle and export the IDevID CSR.
//   hslsa-caliptra-device boot --rom <rom> --fw <bundle> --fuses <unit.json> --out <dir>
//       Cold boot ROM -> FMC -> runtime in the Production lifecycle and read the
//       LDevID, FMC alias and RT alias certificates over the mailbox.
//
// The silicon is caliptra-sw's emulator (caliptra-hw-model). Everything it
// reports comes from running the real ROM and firmware binaries; this program
// only sets fuses, uploads the firmware and asks for certificates.

use anyhow::{anyhow, bail, Context, Result};
use caliptra_api::mailbox::{GetFmcAliasEcc384CertReq, GetLdevEcc384CertReq, GetRtAliasEcc384CertReq};
use caliptra_api::SocManager;
use caliptra_api_types::{DeviceLifecycle, Fuses};
use caliptra_hw_model::{BootParams, HwModel, InitParams, SecurityState};
use caliptra_image_types::ImageManifest;
use serde_json::{json, Value};
use sha2::{Digest, Sha384};
use std::path::{Path, PathBuf};
use std::time::Instant;
use zerocopy::{FromBytes, IntoBytes};

// Set in the DBG_MANUF_SERVICE register to make the ROM export its IDevID CSR.
const GENERATE_IDEVID_CSR: u32 = 1;
const RT_READY: &str = "[rt] RT listening for mailbox commands...\n";
const FIRMWARE_LOAD: u32 = 0x4657_4c44; // "FWLD"
// TCG UEID type RAND; the 16 bytes that follow are the unit serial.
const UEID_TYPE_RAND: u32 = 1;
// Report progress about this often; on the Verilated RTL a boot takes a long time.
const PROGRESS_SECS: u64 = 60;
const POLL_STEPS: u64 = 64;

fn arg(args: &[String], name: &str) -> Result<PathBuf> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| PathBuf::from(&w[1]))
        .ok_or_else(|| anyhow!("missing {name}"))
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn write(dir: &Path, name: &str, data: &[u8]) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(name), data).with_context(|| format!("writing {name}"))
}

fn hex_field(unit: &Value, key: &str, len: usize) -> Result<Vec<u8>> {
    let s = unit[key].as_str().ok_or_else(|| anyhow!("fuse file: {key} missing"))?;
    let b = hex::decode(s).with_context(|| format!("fuse file: {key} is not hex"))?;
    if b.len() != len {
        bail!("fuse file: {key} must be {len} bytes, got {}", b.len());
    }
    Ok(b)
}

fn be_words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    let mut out = [0u32; N];
    for (w, c) in out.iter_mut().zip(bytes.chunks(4)) {
        *w = u32::from_be_bytes(c.try_into().unwrap());
    }
    out
}

/// Fuses and lifecycle for one unit, from the JSON the programming station writes.
fn load_unit(path: &Path) -> Result<(Fuses, SecurityState)> {
    let unit: Value = serde_json::from_slice(&read(path)?)?;
    let serial = unit["serial"].as_str().ok_or_else(|| anyhow!("fuse file: serial missing"))?;
    if serial.len() > 16 {
        bail!("serial {serial} is longer than the 16-byte UEID");
    }
    let mut ueid = [0u8; 16];
    ueid[..serial.len()].copy_from_slice(serial.as_bytes());
    let mut cert_attr = [0u32; 24];
    cert_attr[11] = UEID_TYPE_RAND;
    for (i, c) in ueid.chunks(4).enumerate() {
        cert_attr[12 + i] = u32::from_le_bytes(c.try_into().unwrap());
    }

    let svn_bits = unit["fwSvnFuse"].as_u64().unwrap_or(0) as u32;
    if svn_bits > 32 {
        bail!("fwSvnFuse above 32 is not supported here");
    }
    let lifecycle = match unit["lifecycle"].as_str() {
        Some("manufacturing") => DeviceLifecycle::Manufacturing,
        Some("production") => DeviceLifecycle::Production,
        other => bail!("fuse file: unknown lifecycle {other:?}"),
    };
    let fuses = Fuses {
        uds_seed: be_words(&hex_field(&unit, "udsSeed", 64)?),
        field_entropy: be_words(&hex_field(&unit, "fieldEntropy", 32)?),
        vendor_pk_hash: be_words(&hex_field(&unit, "vendorPkHash", 48)?),
        owner_pk_hash: be_words(&hex_field(&unit, "ownerPkHash", 48)?),
        fw_svn: [if svn_bits == 32 { u32::MAX } else { (1u32 << svn_bits) - 1 }, 0, 0, 0],
        fuse_pqc_key_type: unit["pqcKeyType"].as_u64().unwrap_or(1) as u32,
        idevid_cert_attr: cert_attr,
        life_cycle: lifecycle,
        debug_locked: true,
        ..Default::default()
    };
    let state = *SecurityState::default()
        .set_debug_locked(true)
        .set_device_lifecycle(lifecycle);
    Ok((fuses, state))
}

fn inspect(args: &[String]) -> Result<()> {
    let bundle = read(&arg(args, "--fw")?)?;
    let out = arg(args, "--out")?;
    let (manifest, _) = ImageManifest::read_from_prefix(&bundle)
        .map_err(|_| anyhow!("firmware bundle is shorter than a manifest"))?;
    let mut info = json!({
        "svn": manifest.header.svn,
        "pqcKeyType": manifest.pqc_key_type,
        "vendorEccKeyIndex": manifest.header.vendor_ecc_pub_key_idx,
        "vendorPqcKeyIndex": manifest.header.vendor_pqc_pub_key_idx,
        "vendorPkHash": hex::encode(Sha384::digest(manifest.preamble.vendor_pub_key_info.as_bytes())),
        "ownerPkHash": hex::encode(Sha384::digest(manifest.preamble.owner_pub_keys.as_bytes())),
    });
    for (name, toc) in [("fmc", &manifest.fmc), ("runtime", &manifest.runtime)] {
        let range = toc.offset as usize..(toc.offset + toc.size) as usize;
        let image = bundle.get(range).ok_or_else(|| anyhow!("{name} lies outside the bundle"))?;
        let digest = Sha384::digest(image);
        // The manifest stores each digest as big-endian words; the ROM checks it
        // against the image before running it.
        let listed: Vec<u8> = toc.digest.iter().flat_map(|w| w.to_be_bytes()).collect();
        if listed != digest.as_slice() {
            bail!("{name}: manifest digest does not match the image bytes");
        }
        write(&out, &format!("caliptra-{name}.bin"), image)?;
        info[name] = json!({"file": format!("caliptra-{name}.bin"), "sha384": hex::encode(digest), "size": toc.size});
    }
    write(&out, "fw-manifest.json", serde_json::to_string_pretty(&info)?.as_bytes())?;
    println!("inspect: fmc and runtime written to {}", out.display());
    Ok(())
}

fn csr(args: &[String]) -> Result<()> {
    let rom = read(&arg(args, "--rom")?)?;
    let out = arg(args, "--out")?;
    let (fuses, state) = load_unit(&arg(args, "--fuses")?)?;
    if state.device_lifecycle() != DeviceLifecycle::Manufacturing {
        bail!("the IDevID CSR is only exported in the Manufacturing lifecycle");
    }
    let mut hw = caliptra_hw_model::new(
        InitParams { fuses, rom: &rom, security_state: state, ..Default::default() },
        BootParams { initial_dbg_manuf_service_reg: GENERATE_IDEVID_CSR, ..Default::default() },
    )
    .map_err(|e| anyhow!("model: {e}"))?;
    let start = Instant::now();
    step_until(&mut hw, "ROM, deriving the IDevID key", start, |hw| {
        hw.soc_ifc().cptra_flow_status().read().idevid_csr_ready()
    });
    let mut txn = hw.wait_for_mailbox_receive().map_err(|e| anyhow!("mailbox: {e:?}"))?;
    let envelope = std::mem::take(&mut txn.req.data);
    txn.respond_success();
    // InitDevIdCsrEnvelope: marker, size, then the ECC384 CSR as (len, bytes).
    let len = u32::from_le_bytes(envelope[8..12].try_into()?) as usize;
    let der = envelope.get(12..12 + len).ok_or_else(|| anyhow!("CSR envelope is truncated"))?;
    write(&out, "idevid-csr-ecc384.der", der)?;
    println!("csr: IDevID ECC384 CSR, {len} bytes");
    Ok(())
}

/// Step the device until `done` holds, reporting cycles and the boot status
/// every PROGRESS_SECS, since on the Verilated RTL a boot takes a long time.
///
/// `done` is checked every POLL_STEPS steps: on the RTL a register read is a
/// bus transaction, and polling every cycle only adds bus traffic.
fn step_until<M: HwModel>(hw: &mut M, what: &str, start: Instant, mut done: impl FnMut(&mut M) -> bool) {
    // First report PROGRESS_SECS after this stage starts, not after the boot did.
    let (mut next, mut polls) = (start.elapsed().as_secs() + PROGRESS_SECS, 0u64);
    while !done(hw) {
        for _ in 0..POLL_STEPS {
            hw.step();
        }
        polls += 1;
        if polls % 16 == 0 && start.elapsed().as_secs() >= next {
            next += PROGRESS_SECS;
            // The model's own count includes the cycles bus transactions took.
            let now = hw.output().sink().now();
            let soc = hw.soc_ifc();
            let (boot, flow) = (soc.cptra_boot_status().read(), u32::from(soc.cptra_flow_status().read()));
            let (fatal, non_fatal) = (soc.cptra_fw_error_fatal().read(), soc.cptra_fw_error_non_fatal().read());
            let secs = start.elapsed().as_secs();
            eprintln!("boot: {what}: {now} cycles, {} a second, boot status 0x{boot:x}, flow status 0x{flow:x}, \
                       fw error 0x{fatal:x}/0x{non_fatal:x}, {secs}s", now / secs.max(1));
        }
    }
}

fn boot(args: &[String]) -> Result<()> {
    let rom = read(&arg(args, "--rom")?)?;
    let fw = read(&arg(args, "--fw")?)?;
    let out = arg(args, "--out")?;
    let (fuses, state) = load_unit(&arg(args, "--fuses")?)?;
    let start = Instant::now();
    // Power on and release the boot FSM; the firmware is uploaded below, once
    // the ROM asks for it, so the wait can report progress.
    let mut hw = caliptra_hw_model::new(
        InitParams { fuses, rom: &rom, security_state: state, ..Default::default() },
        BootParams::default(),
    )
    .map_err(|e| anyhow!("model: {e}"))?;
    eprintln!("boot: device model {}", hw.type_name());
    step_until(&mut hw, "ROM, waiting for firmware", start, |hw| hw.ready_for_fw());
    eprintln!("boot: ROM ready for firmware after {} cycles, {:.0}s", hw.output().sink().now(), start.elapsed().as_secs_f64());
    hw.output().set_search_term(RT_READY);
    // FIRMWARE_LOAD, as HwModel::upload_firmware sends it, but waited on here
    // so the ROM's image verification also reports progress.
    hw.start_mailbox_execute(FIRMWARE_LOAD, &fw).map_err(|e| anyhow!("firmware upload: {e}"))?;
    step_until(&mut hw, "ROM, verifying firmware", start, |hw| !hw.soc_mbox().status().read().status().cmd_busy());
    if hw.finish_mailbox_execute().map_err(|e| anyhow!("firmware upload: {e}"))?.is_some() {
        bail!("firmware upload: unexpected response from the ROM");
    }
    eprintln!("boot: firmware accepted by the ROM after {} cycles, {:.0}s", hw.output().sink().now(), start.elapsed().as_secs_f64());
    step_until(&mut hw, "FMC and runtime", start, |hw| hw.output().search_matched());
    let log = hw.output().take(usize::MAX);
    write(&out, "boot.log", log.as_bytes())?;
    eprintln!("boot: runtime ready after {} cycles, {:.0}s", hw.output().sink().now(), start.elapsed().as_secs_f64());

    let ldev = hw.mailbox_execute_req(GetLdevEcc384CertReq::default()).map_err(|e| anyhow!("{e:?}"))?;
    write(&out, "ldevid-ecc384.der", ldev.data().ok_or_else(|| anyhow!("empty LDevID cert"))?)?;
    let fmc = hw.mailbox_execute_req(GetFmcAliasEcc384CertReq::default()).map_err(|e| anyhow!("{e:?}"))?;
    write(&out, "fmc-alias-ecc384.der", fmc.data().ok_or_else(|| anyhow!("empty FMC alias cert"))?)?;
    let rt = hw.mailbox_execute_req(GetRtAliasEcc384CertReq::default()).map_err(|e| anyhow!("{e:?}"))?;
    write(&out, "rt-alias-ecc384.der", rt.data().ok_or_else(|| anyhow!("empty RT alias cert"))?)?;
    let model = json!({"model": hw.type_name(), "seconds": start.elapsed().as_secs()});
    write(&out, "device.json", serde_json::to_string_pretty(&model)?.as_bytes())?;
    println!("boot: runtime ready, LDevID, FMC alias and RT alias certificates read");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("inspect") => inspect(&args[2..]),
        Some("csr") => csr(&args[2..]),
        Some("boot") => boot(&args[2..]),
        _ => bail!("usage: hslsa-caliptra-device inspect|csr|boot ..."),
    }
}
