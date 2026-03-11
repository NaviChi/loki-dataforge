use std::io::Result;
use std::path::Path;

/// High-performance block reader trait that bypasses OS caching if possible.
pub trait DirectBlockReader: Send + Sync {
    /// Read exactly `buf.len()` bytes at `offset`.
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()>;
    /// Read up to `buf.len()` bytes at `offset`, returning the number of bytes read.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize>;
    /// Optional: get logical size of the device/file.
    fn size(&self) -> Result<u64>;
}

/// Create a new `DirectBlockReader` for the given path, utilizing the most
/// efficient OS-specific unbuffered IO mechanism available.
pub fn create_direct_reader<P: AsRef<Path>>(path: P) -> Result<Box<dyn DirectBlockReader>> {
    let path = path.as_ref();
    #[cfg(target_os = "windows")]
    {
        return windows::WindowsDirectReader::new(path);
    }
    #[cfg(target_os = "macos")]
    {
        return macos::MacOsDirectReader::new(path);
    }
    #[cfg(target_os = "linux")]
    {
        return linux::LinuxDirectReader::new(path);
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        return standard::DefaultDirectReader::new(path);
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::prelude::FileExt;

    const FILE_FLAG_NO_BUFFERING: u32 = 0x20000000;
    const FILE_FLAG_RANDOM_ACCESS: u32 = 0x10000000;

    pub struct WindowsDirectReader {
        file: File,
        size: u64,
    }

    impl WindowsDirectReader {
        pub fn new(path: &Path) -> Result<Box<dyn DirectBlockReader>> {
            let file = match OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS)
                .open(path)
            {
                Ok(f) => f,
                // Fallback if sector-aligned rules block unbuffered open
                Err(_) => OpenOptions::new().read(true).open(path)?,
            };
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            Ok(Box::new(Self { file, size }))
        }
    }

    impl DirectBlockReader for WindowsDirectReader {
        fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
            // Note: buf.len() must be aligned if FILE_FLAG_NO_BUFFERING is used
            let read_bytes = self.file.seek_read(buf, offset)?;
            if read_bytes < buf.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Failed to read exact bytes",
                ));
            }
            Ok(())
        }
        fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
            self.file.seek_read(buf, offset)
        }
        fn size(&self) -> Result<u64> {
            Ok(self.size)
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::os::unix::prelude::FileExt;
    use std::os::unix::io::AsRawFd;

    pub struct MacOsDirectReader {
        file: File,
        size: u64,
    }

    impl MacOsDirectReader {
        pub fn new(path: &Path) -> Result<Box<dyn DirectBlockReader>> {
            let file = OpenOptions::new().read(true).open(path)?;
            
            // F_NOCACHE forces direct I/O bypassing the unified buffer cache
            unsafe {
                libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1);
            }
            
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            Ok(Box::new(Self { file, size }))
        }
    }

    impl DirectBlockReader for MacOsDirectReader {
        fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
            self.file.read_exact_at(buf, offset)
        }
        fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
            self.file.read_at(buf, offset)
        }
        fn size(&self) -> Result<u64> {
            Ok(self.size)
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::prelude::FileExt;

    pub struct LinuxDirectReader {
        file: File,
        size: u64,
    }

    impl LinuxDirectReader {
        pub fn new(path: &Path) -> Result<Box<dyn DirectBlockReader>> {
            let file = match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECT)
                .open(path)
            {
                Ok(f) => f,
                Err(_) => OpenOptions::new().read(true).open(path)?,
            };
            
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            Ok(Box::new(Self { file, size }))
        }
    }

    impl DirectBlockReader for LinuxDirectReader {
        fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
            self.file.read_exact_at(buf, offset)
        }
        fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
            self.file.read_at(buf, offset)
        }
        fn size(&self) -> Result<u64> {
            Ok(self.size)
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
mod standard {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::Mutex;

    pub struct DefaultDirectReader {
        file: Mutex<File>,
        size: u64,
    }

    impl DefaultDirectReader {
        pub fn new(path: &Path) -> Result<Box<dyn DirectBlockReader>> {
            let file = std::fs::File::open(path)?;
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            Ok(Box::new(Self { file: Mutex::new(file), size }))
        }
    }

    impl DirectBlockReader for DefaultDirectReader {
        fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
            let mut guard = self.file.lock().unwrap();
            guard.seek(SeekFrom::Start(offset))?;
            guard.read_exact(buf)?;
            Ok(())
        }
        fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
            let mut guard = self.file.lock().unwrap();
            guard.seek(SeekFrom::Start(offset))?;
            guard.read(buf)
        }
        fn size(&self) -> Result<u64> {
            Ok(self.size)
        }
    }
}
