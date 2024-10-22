use std::{
    fs::File,
    io::{self, BufRead, BufReader, BufWriter},
    path::{Path, PathBuf},
};

use clap::Parser;
use eyre::{bail, Context};

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

    let mut inlined_files = vec![];

    map_file_to_output(
        args.input,
        &mut output_file,
        args.link_library,
        false,
        &mut inlined_files,
    )?;

    for inlined_file in &inlined_files {
        println!("Inlined file: {}", inlined_file.display());
    }

    Ok(())
}

fn map_file_to_output(
    input_file: impl AsRef<Path>,
    output: &mut impl io::Write,
    link_library: Vec<PathBuf>,
    supress_pragma: bool,
    already_inlined: &mut Vec<PathBuf>,
) -> eyre::Result<()> {
    let input_file = BufReader::new(
        File::open(input_file.as_ref())
            .with_context(|| format!("while trying to open: {}", input_file.as_ref().display()))?,
    );
    for line in input_file.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.starts_with("pragma circom") && supress_pragma {
            continue;
        }

        if trimmed.starts_with("include") {
            let mut parts = trimmed.split_whitespace();
            parts.next(); // Skip "import"
            let file = parts.next().unwrap();
            let file = file.trim_end_matches(";");
            let file = file.trim_matches('"');

            let (found, path, _, rel_path, _) =
                circom_parser::find_file(file.into(), link_library.clone());
            if !found {
                bail!("Could not find imported file: {}", file);
            }
            if already_inlined.contains(&rel_path) {
                continue;
            }
            already_inlined.push(rel_path.clone());
            writeln!(output, "// Start of inlined file: {}", path)?;
            map_file_to_output(
                rel_path,
                output,
                link_library.clone(),
                true,
                already_inlined,
            )?;
            writeln!(output, "// End of inlined file: {}", path)?;
        } else {
            writeln!(output, "{}", line)?;
        }
    }
    Ok(())
}
