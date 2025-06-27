use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead, BufReader, BufWriter},
    path::{Path, PathBuf},
};

use clap::Parser;
use eyre::{Context, bail};
use sha2::{Digest, Sha256};

#[derive(Debug, Parser)]
struct Args {
    /// The input circom source file to inline
    #[clap(short, long)]
    input: PathBuf,
    /// Additional libraries to link against
    #[clap(short, long)]
    link_library: Vec<PathBuf>,
    /// The output file to write the inlined source to
    #[clap(short, long)]
    output: PathBuf,
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();

    let mut output_file = BufWriter::new(File::create(&args.output)?);

    let mut inlined_files = HashMap::new();

    map_file_to_output(
        args.input,
        &mut output_file,
        args.link_library,
        false,
        &mut inlined_files,
    )?;

    for inlined_file in inlined_files.values() {
        println!("Inlined file: {}", inlined_file.display());
    }

    Ok(())
}

type Hash = [u8; 32];

fn map_file_to_output(
    input_file: impl AsRef<Path>,
    output: &mut impl io::Write,
    link_library: Vec<PathBuf>,
    suppress_pragma: bool,
    already_inlined: &mut HashMap<Hash, PathBuf>,
) -> eyre::Result<()> {
    let input_file_reader = BufReader::new(
        File::open(input_file.as_ref())
            .with_context(|| format!("while trying to open: {}", input_file.as_ref().display()))?,
    );
    for line in input_file_reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.starts_with("pragma circom") && suppress_pragma {
            continue;
        }

        if trimmed.starts_with("include") {
            let mut parts = trimmed.split_whitespace();
            parts.next(); // Skip "include"
            let file = parts.next().unwrap();
            let file = file.trim_end_matches(";");
            let file = file.trim_matches('"');
            let mut link_library_local = link_library.clone();
            link_library_local.push(
                input_file
                    .as_ref()
                    .parent()
                    .expect("input file to have a parent directory")
                    .to_path_buf(),
            );

            let (found, path, _, rel_path, _) =
                circom_parser::find_file(file.into(), link_library_local.clone());
            if !found {
                bail!("Could not find imported file: {}", file);
            }
            let file_hash = hash_file(&rel_path)?;
            if already_inlined.contains_key(&file_hash) {
                continue;
            }
            already_inlined.insert(file_hash, rel_path.clone());
            writeln!(output, "// Start of inlined file: {path}")?;
            map_file_to_output(
                rel_path,
                output,
                link_library.clone(),
                true,
                already_inlined,
            )?;
            writeln!(output, "// End of inlined file: {path}")?;
        } else {
            writeln!(output, "{line}")?;
        }
    }
    Ok(())
}

fn hash_file(file_name: impl AsRef<Path>) -> eyre::Result<Hash> {
    let mut hasher = Sha256::new();
    let mut file = BufReader::new(File::open(file_name.as_ref()).with_context(|| {
        format!(
            "while trying to open file {} for hashing",
            file_name.as_ref().display()
        )
    })?);

    std::io::copy(&mut file, &mut hasher)
        .with_context(|| format!("while hashing file {}", file_name.as_ref().display()))?;
    Ok(hasher.finalize().into())
}
