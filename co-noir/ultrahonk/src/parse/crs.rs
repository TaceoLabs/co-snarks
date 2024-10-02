//  modified from barustenberg:

use crate::types::Crs;
use crate::types::ProverCrs;
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_serialize::CanonicalDeserialize;
use byteorder::ByteOrder;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;
use byteorder::{BigEndian, LittleEndian};
use eyre::{anyhow, Result};
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::marker::PhantomData;
use std::path::Path;

pub type CrsParser<P> = NewFileStructure<P>;

const BLAKE2B_CHECKSUM_LENGTH: usize = 64;
#[derive(Debug, Default)]
struct Manifest {
    transcript_number: u32,
    total_transcripts: u32,
    total_g1_points: u32,
    total_g2_points: u32,
    num_g1_points: u32,
    num_g2_points: u32,
    start_from: u32,
}

// Barretenberg changed the structure for the .dat files, therefore there are two slightly different implementations
// the new one (when installing) barretenberg can be found under ~/.bb-crs (or downloaded from https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/flat/g1.dat or g2.dat, but the first one is 6 gb large)
// the older ones can be downloaded with ~/aztec-packages/barretenberg/cpp/srs_db/download_srs.sh (iirc), these are separated into 20 files, for info see also ~/aztec-packages/barretenberg/cpp/srs_db/transcript_spec.md

pub struct NewFileStructure<P: Pairing> {
    phantom_data: PhantomData<P>,
}

impl<P: Pairing> NewFileStructure<P> {
    pub fn get_crs(path_g1: &str, path_g2: &str, crs_size: usize) -> Result<Crs<P>> {
        let mut monomials: Vec<P::G1Affine> = vec![P::G1Affine::default(); crs_size + 2];
        let mut g2_x = P::G2Affine::default();
        Self::read_transcript(&mut monomials, &mut g2_x, crs_size, path_g1, path_g2)?;

        Ok(Crs { monomials, g2_x })
    }

    pub fn get_crs_g1(path_g1: &str, crs_size: usize) -> Result<ProverCrs<P>> {
        let mut monomials: Vec<P::G1Affine> = vec![P::G1Affine::default(); crs_size + 2];
        Self::read_transcript_g1(&mut monomials, crs_size, path_g1)?;

        Ok(ProverCrs { monomials })
    }
}

fn get_file_size(filename: &str) -> std::io::Result<u64> {
    let metadata = std::fs::metadata(filename)?;
    Ok(metadata.len())
}

trait FileProcessor<P: Pairing> {
    fn read_transcript_g1(monomials: &mut [P::G1Affine], degree: usize, dir: &str) -> Result<()>;
    fn read_transcript_g2(g2_x: &mut P::G2Affine, dir: &str) -> Result<()>;
    fn read_transcript(
        monomials: &mut [<P as Pairing>::G1Affine],
        g2_x: &mut <P as Pairing>::G2Affine,
        degree: usize,
        path_g1: &str,
        path_g2: &str,
    ) -> Result<()> {
        Self::read_transcript_g1(monomials, degree, path_g1)?;
        Self::read_transcript_g2(g2_x, path_g2)?;
        Ok(())
    }
    fn read_elements_from_buffer<G: AffineRepr>(elements: &mut [G], buffer: &mut [u8]) {
        for (element, chunk) in elements.iter_mut().zip(buffer.chunks_exact_mut(64)) {
            Self::convert_endianness_inplace(chunk);
            #[allow(clippy::redundant_slicing)]
            if let Ok(val) = G::deserialize_uncompressed_unchecked(&chunk[..]) {
                *element = val;
            }
        }
    }
    fn get_transcript_size(manifest: &Manifest) -> usize {
        let manifest_size = std::mem::size_of::<Manifest>();
        let g1_buffer_size = std::mem::size_of::<<P::G1 as CurveGroup>::BaseField>()
            * 2
            * manifest.num_g1_points as usize;
        let g2_buffer_size = std::mem::size_of::<<P::G2 as CurveGroup>::BaseField>()
            * 2
            * manifest.num_g2_points as usize;
        manifest_size + g1_buffer_size + g2_buffer_size + BLAKE2B_CHECKSUM_LENGTH
    }

    fn read_manifest(filename: &str) -> Result<Manifest> {
        let mut file = File::open(filename)?;

        Ok(Manifest {
            transcript_number: file.read_u32::<BigEndian>()?,
            total_transcripts: file.read_u32::<BigEndian>()?,
            total_g1_points: file.read_u32::<BigEndian>()?,
            total_g2_points: file.read_u32::<BigEndian>()?,
            num_g1_points: file.read_u32::<BigEndian>()?,
            num_g2_points: file.read_u32::<BigEndian>()?,
            start_from: file.read_u32::<BigEndian>()?,
        })
    }

    fn write_manifest(filename: &str, manifest: &Manifest) -> Result<()> {
        let mut file = File::create(filename)?;

        // Here you need to call file.write_u32::<BigEndian>(value)? for each field in Manifest
        file.write_u32::<BigEndian>(manifest.transcript_number)?;
        file.write_u32::<BigEndian>(manifest.total_transcripts)?;
        file.write_u32::<BigEndian>(manifest.total_g1_points)?;
        file.write_u32::<BigEndian>(manifest.total_g2_points)?;
        file.write_u32::<BigEndian>(manifest.num_g1_points)?;
        file.write_u32::<BigEndian>(manifest.num_g2_points)?;
        file.write_u32::<BigEndian>(manifest.start_from)?;

        Ok(())
    }
    fn convert_endianness_inplace(buffer: &mut [u8]);
}

impl<P: Pairing> FileProcessor<P> for NewFileStructure<P> {
    fn read_transcript_g1(
        monomials: &mut [<P as Pairing>::G1Affine],
        degree: usize,
        path: &str,
    ) -> Result<()> {
        let g1_file_size = get_file_size(path)? as usize;
        assert!(g1_file_size % 64 == 0); //g1_file_size >= num_points * 64 &&
        let num_to_read = degree; //g1_file_size / 64;
        let g1_buffer_size =
            std::mem::size_of::<<P::G1 as CurveGroup>::BaseField>() * 2 * num_to_read;
        let mut buffer = vec![0_u8; g1_buffer_size];

        let file = File::open(path)?;
        let mut file = file.take(g1_buffer_size as u64);
        assert!(Path::new(&path).exists());
        file.read_exact(&mut buffer[..])?;
        // We must pass the size actually read to the second call, not the desired
        // g1_buffer_size as the file may have been smaller than this.
        let monomials = &mut monomials[0..];
        Self::read_elements_from_buffer(monomials, &mut buffer);
        Ok(())
    }

    fn read_transcript_g2(g2_x: &mut P::G2Affine, path: &str) -> Result<()> {
        let g2_size = std::mem::size_of::<<P::G2 as CurveGroup>::BaseField>() * 2;

        assert!(std::mem::size_of::<P::G2Affine>() >= g2_size);
        let mut buffer = vec![0; g2_size];

        let file = File::open(path)?;
        let mut file = file.take(g2_size as u64);
        file.read_exact(&mut buffer[..])?;
        Self::convert_endianness_inplace(&mut buffer);
        *g2_x = P::G2Affine::deserialize_uncompressed(&mut &buffer[..])
            .map_err(|e| anyhow!("Failed to deserialize G2Affine from transcript file: {}", e))?;
        Ok(())
    }

    // I don't think this is the nicest way, but the data is arranged slightly different as before
    fn convert_endianness_inplace(buffer: &mut [u8]) {
        for chunk in buffer.chunks_mut(32) {
            if chunk.len() == 32 {
                let mut reversed = [0u8; 32];
                for i in 0..4 {
                    let start = i * 8;
                    let end = (i + 1) * 8;
                    let reverse_start = chunk.len() - end;
                    let reverse_end = chunk.len() - start;
                    reversed[start..end].copy_from_slice(&chunk[reverse_start..reverse_end]);
                }

                for i in 0..4 {
                    let start = i * 8;
                    let end = (i + 1) * 8;
                    let be = BigEndian::read_u64(&reversed[start..end]);
                    LittleEndian::write_u64(&mut chunk[start..end], be);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Bn254, Fq12, G1Affine, G2Affine};
    use ark_ec::{pairing::Pairing, AffineRepr};
    use ark_ff::Field;

    use crate::parse::crs::{FileProcessor, NewFileStructure};
    #[test]
    fn read_transcript_loads_well_formed_srs_new() {
        let degree = 1000;
        let mut monomials: Vec<G1Affine> = vec![G1Affine::default(); degree + 2];
        let mut g2_x = G2Affine::default();
        NewFileStructure::<Bn254>::read_transcript(
            &mut monomials,
            &mut g2_x,
            degree,
            "crs/bn254_g1.dat",
            "crs/bn254_g2.dat",
        )
        .unwrap();
        assert_eq!(G1Affine::generator(), monomials[0]);
        let mut p: Vec<G1Affine> = vec![monomials[1], G1Affine::generator()];
        let q: Vec<G2Affine> = vec![G2Affine::generator(), g2_x];
        p[0].y.neg_in_place();

        let res = Bn254::multi_pairing(&p, &q).0;
        assert_eq!(res, Fq12::ONE);
        for mon in monomials.iter().take(degree) {
            assert!(mon.is_on_curve());
        }
    }
}
