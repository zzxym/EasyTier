#[cfg(target_os = "windows")]
use std::process::Command;
use std::{env, io::Cursor, path::PathBuf};

#[cfg(target_os = "windows")]
struct WindowsBuild {}

#[cfg(target_os = "windows")]
impl WindowsBuild {
    // 获取protoc的include目录路径
    fn get_protoc_include_path(protoc_path: &PathBuf) -> Option<PathBuf> {
        // 尝试从protoc命令获取版本信息并推断include路径
        let output = Command::new(protoc_path)
            .arg("--version")
            .output()
            .ok()?;
            
        if !output.status.success() {
            return None;
        }
        
        // 尝试几种可能的include路径位置
        // 1. 从WinGet安装的典型位置
        let winget_include_path = PathBuf::from("C:\\Program Files\\protobuf\\include");
        if winget_include_path.exists() {
            println!("cargo:info=Found protobuf include path at: {:?}", winget_include_path);
            return Some(winget_include_path);
        }
        
        // 2. 相对于protoc.exe的位置
        if let Some(parent) = protoc_path.parent() {
            let include_path = parent.join("include");
            if include_path.exists() {
                println!("cargo:info=Found protobuf include path at: {:?}", include_path);
                return Some(include_path);
            }
        }
        
        // 3. 默认的系统路径
        let default_paths = [
            PathBuf::from("C:\\Program Files\\Protocol Buffers\\include"),
            PathBuf::from("C:\\Program Files (x86)\\Protocol Buffers\\include"),
        ];
        
        for path in &default_paths {
            if path.exists() {
                println!("cargo:info=Found protobuf include path at: {:?}", path);
                return Some(path.clone());
            }
        }
        
        println!("cargo:warning=Failed to find protobuf include path");
        None
    }
    
    fn check_protoc_exist() -> Option<PathBuf> {
        let path = env::var_os("PROTOC").map(PathBuf::from);
        if path.is_some() && path.as_ref().unwrap().exists() {
            return path;
        }

        let path = env::var_os("PATH").unwrap_or_default();
        for p in env::split_paths(&path) {
            let p = p.join("protoc.exe");
            if p.exists() && p.is_file() {
                return Some(p);
            }
        }

        None
    }

    fn get_cargo_target_dir() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
        let profile = std::env::var("PROFILE")?;
        let mut target_dir = None;
        let mut sub_path = out_dir.as_path();
        while let Some(parent) = sub_path.parent() {
            if parent.ends_with(&profile) {
                target_dir = Some(parent);
                break;
            }
            sub_path = parent;
        }
        let target_dir = target_dir.ok_or("not found")?;
        Ok(target_dir.to_path_buf())
    }

    fn download_protoc() -> PathBuf {
        println!("cargo:info=use exist protoc: {:?}", "k");
        let out_dir = Self::get_cargo_target_dir().unwrap().join("protobuf");
        let fname = out_dir.join("bin/protoc.exe");
        if fname.exists() {
            println!("cargo:info=use exist protoc: {:?}", fname);
            return fname;
        }

        println!("cargo:info=need download protoc, please wait...");

        let url = "https://github.com/protocolbuffers/protobuf/releases/download/v26.0-rc1/protoc-26.0-rc-1-win64.zip";
        let response = reqwest::blocking::get(url).unwrap();
        println!("{:?}", response);
        let mut content = response
            .bytes()
            .map(|v| v.to_vec())
            .map(Cursor::new)
            .map(zip::ZipArchive::new)
            .unwrap()
            .unwrap();
        content.extract(out_dir).unwrap();

        fname
    }

    pub fn check_for_win() {
        // add third_party dir to link search path
        let target = std::env::var("TARGET").unwrap_or_default();
        println!("cargo:info=TARGET: {:?}", target);

        if target.contains("x86_64") {
            println!("cargo:rustc-link-search=native=easytier/third_party/");
        } else if target.contains("i686") {
            println!("cargo:rustc-link-search=native=easytier/third_party/i686/");
        } else if target.contains("aarch64") {
            println!("cargo:rustc-link-search=native=easytier/third_party/arm64/");
        }

        let protoc_path = if let Some(o) = Self::check_protoc_exist() {
            println!("cargo:info=use os exist protoc: {:?}", o);
            o
        } else {
            Self::download_protoc()
        };
        println!("cargo:info=Setting PROTOC to: {:?}", protoc_path);
        std::env::set_var("PROTOC", &protoc_path);
        println!("cargo:info=PROTOC set successfully");
        
        // 尝试设置PROTOBUF_INCLUDE路径
        if let Some(include_path) = Self::get_protoc_include_path(&protoc_path) {
            println!("cargo:info=Setting PROTOBUF_INCLUDE to: {:?}", include_path);
            std::env::set_var("PROTOBUF_INCLUDE", include_path);
        }
    }
}

fn workdir() -> Option<String> {
    if let Ok(cargo_manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        return Some(cargo_manifest_dir);
    }

    let dest = std::env::var("OUT_DIR");
    if dest.is_err() {
        return None;
    }
    let dest = dest.unwrap();

    let seperator = regex::Regex::new(r"(/target/(.+?)/build/)|(\\target\\(.+?)\\build\\)")
        .expect("Invalid regex");
    let parts = seperator.split(dest.as_str()).collect::<Vec<_>>();

    if parts.len() >= 2 {
        return Some(parts[0].to_string());
    }

    None
}

fn check_locale() {
    let workdir = workdir().unwrap_or("./".to_string());

    let locale_path = format!("{workdir}/**/locales/**/*");
    if let Ok(globs) = globwalk::glob(locale_path) {
        for entry in globs {
            if let Err(e) = entry {
                println!("cargo:i18n-error={e}");
                continue;
            }

            let entry = entry.unwrap().into_path();
            println!("cargo:rerun-if-changed={}", entry.display());
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // enable thunk-rs when target os is windows and arch is x86_64 or i686
    #[cfg(target_os = "windows")]
    if !std::env::var("TARGET")
        .unwrap_or_default()
        .contains("aarch64")
    {
        thunk::thunk();
    }

    #[cfg(target_os = "windows")]
    WindowsBuild::check_for_win();

    let proto_files_reflect = ["src/proto/peer_rpc.proto", "src/proto/common.proto"];

    let proto_files = [
        "src/proto/error.proto",
        "src/proto/tests.proto",
        "src/proto/api_instance.proto",
        "src/proto/api_logger.proto",
        "src/proto/api_config.proto",
        "src/proto/api_manage.proto",
        "src/proto/web.proto",
        "src/proto/magic_dns.proto",
        "src/proto/acl.proto",
    ];

    for proto_file in proto_files.iter().chain(proto_files_reflect.iter()) {
        println!("cargo:rerun-if-changed={proto_file}");
    }

    let mut config = prost_build::Config::new();
    config
        .protoc_arg("--experimental_allow_proto3_optional")
        .type_attribute(".acl", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".common", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".error", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".api", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".web", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".config", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(
            "peer_rpc.GetIpListResponse",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute("peer_rpc.DirectConnectedPeerInfo", "#[derive(Hash)]")
        .type_attribute("peer_rpc.PeerInfoForGlobalMap", "#[derive(Hash)]")
        .type_attribute("peer_rpc.ForeignNetworkRouteInfoKey", "#[derive(Hash, Eq)]")
        .type_attribute(
            "peer_rpc.RouteForeignNetworkSummary.Info",
            "#[derive(Hash, Eq, serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute(
            "peer_rpc.RouteForeignNetworkSummary",
            "#[derive(Hash, Eq, serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute("common.RpcDescriptor", "#[derive(Hash, Eq)]")
        .field_attribute(".api.manage.NetworkConfig", "#[serde(default)]")
        .service_generator(Box::new(rpc_build::ServiceGenerator::new()))
        .btree_map(["."])
        .skip_debug([".common.Ipv4Addr", ".common.Ipv6Addr", ".common.UUID"]);

    println!("cargo:info=Compiling protos with proto_files: {:?}", proto_files);
    
    // 构建包含路径列表，包括src/proto和可能的系统protobuf include路径
    let mut proto_include_paths = vec!["src/proto/".to_string()];
    
    // 检查是否有设置PROTOBUF_INCLUDE环境变量
    if let Ok(protobuf_include) = std::env::var("PROTOBUF_INCLUDE") {
        println!("cargo:info=Using PROTOBUF_INCLUDE: {:?}", protobuf_include);
        proto_include_paths.push(protobuf_include);
    }
    
    // 转换为&str切片用于compile_protos
    let include_paths: Vec<&str> = proto_include_paths.iter().map(|s| s.as_str()).collect();
    println!("cargo:info=Final proto include paths: {:?}", include_paths);
    
    config.compile_protos(&proto_files, &include_paths)?;

    println!("cargo:info=Compiling reflection protos with proto_files_reflect: {:?}", proto_files_reflect);
    prost_reflect_build::Builder::new()
        .file_descriptor_set_bytes("crate::proto::DESCRIPTOR_POOL_BYTES")
        .compile_protos_with_config(config, &proto_files_reflect, &include_paths)?;
    
    println!("cargo:info=All proto compilation completed successfully");

    check_locale();
    Ok(())
}
