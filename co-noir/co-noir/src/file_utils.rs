use std::path::{Path, PathBuf};

/// An error type for file utility functions.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file was not found.
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),
    /// The directory was not found.
    #[error("Dir not found: {0}")]
    DirNotFound(PathBuf),
    /// The path was expected to be a directory, but it is a file.
    #[error("Expected {0} to be a directory, but it is a file.")]
    ExpectedDir(PathBuf),
    /// The path was expected to be a file, but it is a directory.
    #[error("Expected {0} to be a file, but it is a directory.")]
    ExpectedFile(PathBuf),
    /// An I/O error occurred.
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

/// Check if a file exists at the given path, and is actually a file.
pub fn check_file_exists(file_path: &Path) -> Result<(), Error> {
    if !file_path.exists() {
        return Err(Error::FileNotFound(file_path.to_path_buf()));
    }
    if !file_path.is_file() {
        return Err(Error::ExpectedFile(file_path.to_path_buf()));
    }
    Ok(())
}

/// Check if a directory exists at the given path, and is actually a directory.
pub fn check_dir_exists(dir_path: &Path) -> Result<(), Error> {
    if !dir_path.exists() {
        return Err(Error::DirNotFound(dir_path.to_path_buf()));
    }
    if !dir_path.is_dir() {
        return Err(Error::ExpectedDir(dir_path.to_path_buf()));
    }
    Ok(())
}
