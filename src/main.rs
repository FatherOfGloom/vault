use std::{
    fs::{self},
    io::ErrorKind,
};

const COMPATIBLE_VERSION: u32 = 0;

struct Storage<'a> {
    metadata: Option<RawMetadata<'a>>,
    data: Vec<u8>,
}

macro_rules! exit {
    () => {
       std::process::exit(1);
    };
    ($($s:tt)*) => {{
        eprintln!($($s)*);
        std::process::exit(1);
    }};
}

impl Storage<'_> {
    fn new() -> Self {
        let data = Self::read_file("vault").unwrap_or_default();

        Storage {
            data,
            metadata: None,
        }
    }

    fn compatible(&self, executable_version: u32) -> bool {
        match self.metadata.as_ref().unwrap().version() {
            CompatibleVersion::Any => true,
            CompatibleVersion::One(version) if version == executable_version => true,
            _ => false,
        }
    }

    fn version(&self) -> u32 {
        match self.metadata.as_ref().unwrap().version() {
            CompatibleVersion::Any => COMPATIBLE_VERSION,
            CompatibleVersion::One(num) => num,
        }
    }

    fn read_file(file_path: &str) -> Option<Vec<u8>> {
        match fs::read(file_path) {
            Ok(vec) => Some(vec),
            Err(e) => match e.kind() {
                ErrorKind::NotFound => None,
                // TODO: return Vaulterr::IoError
                _ => exit!("Unable to open vault data: {}", e.to_string()),
            },
        }
    }
}

enum VaultErr {
    IoErr(std::io::Error),
    InnerError(String),
    UserError(String),
}

impl std::fmt::Display for VaultErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultErr::IoErr(error) => write!(f, "{}", error),
            VaultErr::InnerError(error) => write!(f, "{}", error),
            VaultErr::UserError(error) => write!(f, "{}", error),
        }
    }
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<(), VaultErr> {
    let args: Vec<_> = args.collect();

    let mut storage = Storage::new();
    
    storage.metadata = Some(RawMetadata::extract(&storage.data).unwrap());

    if !storage.compatible(COMPATIBLE_VERSION) {
        return Err(VaultErr::InnerError(format!(
            "Incompatible versions. Storage version: {}, Executable version: {}",
            storage.version(),
            COMPATIBLE_VERSION
        )));
    }

    let cmd = match args.len() {
        2 => {
            let password = args.get(1).unwrap();

            // TODO: process password
        }
        3 => {}
        _ => {
            return Err(VaultErr::UserError(
                "Invalid number of arguments".to_string(),
            ));
        }
    };

    Ok(())
}

struct RawMetadata<'a> {
    compatible_version: CompatibleVersion,
    metahash: Option<&'a [u8]>,
    password_hash: Option<&'a [u8]>,
}

#[derive(Clone, Copy)]
enum CompatibleVersion {
    Any,
    One(u32),
}

impl<'a> RawMetadata<'a> {
    fn extract(data: &'a [u8]) -> Result<RawMetadata<'a>, &'static str> {
        if data.is_empty() {
            Ok(RawMetadata {
                compatible_version: CompatibleVersion::Any,
                metahash: None,
                password_hash: None,
            })
        } else {
            todo!();
        }
    }

    fn version(&self) -> CompatibleVersion {
        self.compatible_version
    }
}

fn main() {
    let args = std::env::args();

    parse_args(args).unwrap_or_else(|e| {
        // TODO: print usage on user error
        eprintln!("{}", e.to_string());
        exit!("Usage: vault [password]");
    });
}
