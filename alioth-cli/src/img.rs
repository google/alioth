// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::Path;

use alioth::blk::qcow2::{
    QCOW2_MAGIC, Qcow2CmprDesc, Qcow2Hdr, Qcow2IncompatibleFeatures, Qcow2L1, Qcow2L2, Qcow2StdDesc,
};
use alioth::errors::{DebugTrace, trace_error};
use alioth::utils::endian::Bu64;
use clap::{Args, Subcommand};
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress};
use serde::Deserialize;
use snafu::{ResultExt, Snafu};
use zerocopy::{FromZeros, IntoBytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum ImageFormat {
    #[serde(alias = "qcow2")]
    Qcow2,
    #[serde(alias = "raw")]
    Raw,
}

#[derive(Args, Debug)]
pub struct ImgArgs {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Convert an image from one format to another.
    Convert(ConvertArgs),
}

#[derive(Args, Debug)]
struct ConvertArgs {
    /// Input file format
    #[arg(short = 'f', long, default_value = "qcow2")]
    source_format: Box<str>,

    /// Output file format
    #[arg(short = 'O', long, default_value = "raw")]
    target_format: Box<str>,

    /// Input file
    input: Box<Path>,

    /// Output file
    output: Box<Path>,
}

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Error from OS"), context(false))]
    System { error: std::io::Error },
    #[snafu(display("Failed to parse {arg}"))]
    ParseArg {
        arg: String,
        error: serde_aco::Error,
    },
    #[snafu(display("Failed to convert image from {from:?} to {to:?}"))]
    Conversion { from: ImageFormat, to: ImageFormat },
    #[snafu(display("Missing magic number {magic:x?}, found {found:x?}"))]
    MissingMagic { magic: [u8; 4], found: [u8; 4] },
    #[snafu(display("Unsupported qcow2 features: {features:?}"))]
    Features { features: Qcow2IncompatibleFeatures },
    #[snafu(display("Decompression failed: {:?}", status))]
    DecompressionFailed { status: TINFLStatus },
}

type Result<T> = std::result::Result<T, Error>;

pub fn exec(args: ImgArgs) -> Result<()> {
    match args.cmd {
        Command::Convert(args) => convert(args),
    }
}

fn convert(args: ConvertArgs) -> Result<()> {
    let from: ImageFormat = serde_aco::from_arg(&args.source_format).context(error::ParseArg {
        arg: args.source_format,
    })?;
    let to: ImageFormat = serde_aco::from_arg(&args.target_format).context(error::ParseArg {
        arg: args.target_format,
    })?;
    if from == ImageFormat::Qcow2 && to == ImageFormat::Raw {
        convert_qcow2_to_raw(&args.input, &args.output)
    } else {
        error::Conversion { from, to }.fail()
    }
}

fn convert_qcow2_to_raw(input: &Path, output: &Path) -> Result<()> {
    let mut hdr = Qcow2Hdr::new_zeroed();
    let mut f = File::open(input)?;
    f.read_exact(hdr.as_mut_bytes())?;
    if hdr.magic != QCOW2_MAGIC {
        return error::MissingMagic {
            magic: QCOW2_MAGIC,
            found: hdr.magic,
        }
        .fail();
    }
    let features = hdr.incompatible_features.to_ne();
    if hdr.version.to_ne() > 2 && features != 0 {
        let features = Qcow2IncompatibleFeatures::from_bits_retain(features);
        return error::Features { features }.fail();
    }
    let cluster_bits = hdr.cluster_bits.to_ne();
    let cluster_size = 1 << cluster_bits;
    let l2_size = cluster_size / std::mem::size_of::<Bu64>() as u64;

    let mut l1_table = vec![Bu64::new_zeroed(); hdr.l1_size.to_ne() as usize];
    f.read_exact_at(l1_table.as_mut_bytes(), hdr.l1_table_offset.to_ne())?;

    let output = File::create(output)?;
    output.set_len(hdr.size.to_ne())?;

    let mut data = vec![0u8; cluster_size as usize];
    let mut tmp_buf = vec![0u8; cluster_size as usize];
    let mut l2_table = vec![Bu64::new_zeroed(); l2_size as usize];

    let mut decompressor = DecompressorOxide::new();

    for (l1_index, l1_entry) in l1_table.iter().enumerate() {
        let l1_entry = Qcow2L1(l1_entry.to_ne());
        let l2_offset = l1_entry.l2_offset();
        if l2_offset == 0 {
            continue;
        }
        f.read_exact_at(l2_table.as_mut_bytes(), l2_offset)?;
        for (l2_index, l2_entry) in l2_table.iter().enumerate() {
            let l2_entry = Qcow2L2(l2_entry.to_ne());
            if l2_entry.compressed() {
                let l2_desc = Qcow2CmprDesc(l2_entry.desc());
                let (offset, size) = l2_desc.offset_size(cluster_bits);
                let buf = if let Some(buf) = tmp_buf.get_mut(..size as usize) {
                    buf
                } else {
                    tmp_buf.resize(size as usize, 0);
                    tmp_buf.as_mut()
                };
                f.read_exact_at(buf, offset)?;
                decompressor.init();
                let flag = TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
                let (status, _, _) = decompress(&mut decompressor, buf, &mut data, 0, flag);
                if status != TINFLStatus::Done {
                    return error::DecompressionFailed { status }.fail();
                }
            } else {
                let l2_desc = Qcow2StdDesc(l2_entry.desc());
                if l2_desc.zero() {
                    continue;
                }
                if !l2_entry.rc1() && l2_desc.offset() == 0 {
                    continue;
                }
                let offset = l2_desc.cluster_offset();
                f.read_exact_at(&mut data, offset)?;
            }
            let output_offset = (l1_index as u64 * l2_size + l2_index as u64) << cluster_bits;
            output.write_all_at(&data, output_offset)?;
        }
    }
    Ok(())
}
