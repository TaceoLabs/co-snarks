use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),
    #[error("Dir not found: {0}")]
    DirNotFound(PathBuf),
    #[error("Expected {0} to be a directory, but it is a file.")]
    ExpectedDir(PathBuf),
    #[error("Expected {0} to be a file, but it is a directory.")]
    ExpectedFile(PathBuf),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

pub fn check_file_exists(file_path: &Path) -> Result<(), Error> {
    if !file_path.exists() {
        return Err(Error::FileNotFound(file_path.to_path_buf()));
    }
    if !file_path.is_file() {
        return Err(Error::ExpectedFile(file_path.to_path_buf()));
    }
    Ok(())
}

pub fn check_dir_exists(dir_path: &Path) -> Result<(), Error> {
    if !dir_path.exists() {
        return Err(Error::DirNotFound(dir_path.to_path_buf()));
    }
    if !dir_path.is_dir() {
        return Err(Error::ExpectedDir(dir_path.to_path_buf()));
    }
    Ok(())
}
