use crate::{
    common::config::ConfigLoader,
    instance_manager::NetworkInstanceManager,
    launcher::ConfigSource,
    proto::{
        rpc_types::{self, controller::BaseController},
        web::{
            CollectNetworkInfoRequest, CollectNetworkInfoResponse, DeleteNetworkInstanceRequest,
            DeleteNetworkInstanceResponse, GetConfigRequest, GetConfigResponse,
            ListNetworkInstanceRequest, ListNetworkInstanceResponse, NetworkInstanceRunningInfoMap,
            ReplaceConfigRequest, ReplaceConfigResponse, RetainNetworkInstanceRequest,
            RetainNetworkInstanceResponse, RunNetworkInstanceRequest, RunNetworkInstanceResponse,
            ValidateConfigRequest, ValidateConfigResponse, WebClientService,
        },
    },
};

pub struct Controller {
    token: String,
    hostname: String,
    manager: NetworkInstanceManager,
}

impl Controller {
    pub fn new(token: String, hostname: String) -> Self {
        Controller {
            token,
            hostname,
            manager: NetworkInstanceManager::new(),
        }
    }

    pub fn list_network_instance_ids(&self) -> Vec<uuid::Uuid> {
        self.manager.list_network_instance_ids()
    }

    pub fn token(&self) -> String {
        self.token.clone()
    }

    pub fn hostname(&self) -> String {
        self.hostname.clone()
    }
}

#[async_trait::async_trait]
impl WebClientService for Controller {
    type Controller = BaseController;

    async fn validate_config(
        &self,
        _: BaseController,
        req: ValidateConfigRequest,
    ) -> Result<ValidateConfigResponse, rpc_types::error::Error> {
        let toml_config = req.config.unwrap_or_default().gen_config()?.dump();
        Ok(ValidateConfigResponse { toml_config })
    }

    async fn run_network_instance(
        &self,
        _: BaseController,
        req: RunNetworkInstanceRequest,
    ) -> Result<RunNetworkInstanceResponse, rpc_types::error::Error> {
        if req.config.is_none() {
            return Err(anyhow::anyhow!("config is required").into());
        }
        let cfg = req.config.unwrap().gen_config()?;
        let id = cfg.get_id();
        if let Some(inst_id) = req.inst_id {
            cfg.set_id(inst_id.into());
        }
        self.manager.run_network_instance(cfg, ConfigSource::Web)?;
        println!("instance {} started", id);
        Ok(RunNetworkInstanceResponse {
            inst_id: Some(id.into()),
        })
    }

    async fn retain_network_instance(
        &self,
        _: BaseController,
        req: RetainNetworkInstanceRequest,
    ) -> Result<RetainNetworkInstanceResponse, rpc_types::error::Error> {
        let remain = self
            .manager
            .retain_network_instance(req.inst_ids.into_iter().map(Into::into).collect())?;
        println!("instance {:?} retained", remain);
        Ok(RetainNetworkInstanceResponse {
            remain_inst_ids: remain.iter().map(|item| (*item).into()).collect(),
        })
    }

    async fn collect_network_info(
        &self,
        _: BaseController,
        req: CollectNetworkInfoRequest,
    ) -> Result<CollectNetworkInfoResponse, rpc_types::error::Error> {
        let mut ret = NetworkInstanceRunningInfoMap {
            map: self
                .manager
                .collect_network_infos()?
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        };
        let include_inst_ids = req
            .inst_ids
            .iter()
            .cloned()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();
        if !include_inst_ids.is_empty() {
            let mut to_remove = Vec::new();
            for (k, _) in ret.map.iter() {
                if !include_inst_ids.contains(k) {
                    to_remove.push(k.clone());
                }
            }

            for k in to_remove {
                ret.map.remove(&k);
            }
        }
        Ok(CollectNetworkInfoResponse { info: Some(ret) })
    }

    //   rpc ListNetworkInstance(ListNetworkInstanceRequest) returns (ListNetworkInstanceResponse) {}
    async fn list_network_instance(
        &self,
        _: BaseController,
        _: ListNetworkInstanceRequest,
    ) -> Result<ListNetworkInstanceResponse, rpc_types::error::Error> {
        Ok(ListNetworkInstanceResponse {
            inst_ids: self
                .manager
                .list_network_instance_ids()
                .into_iter()
                .map(Into::into)
                .collect(),
        })
    }

    //   rpc DeleteNetworkInstance(DeleteNetworkInstanceRequest) returns (DeleteNetworkInstanceResponse) {}
    async fn delete_network_instance(
        &self,
        _: BaseController,
        req: DeleteNetworkInstanceRequest,
    ) -> Result<DeleteNetworkInstanceResponse, rpc_types::error::Error> {
        let remain_inst_ids = self
            .manager
            .delete_network_instance(req.inst_ids.into_iter().map(Into::into).collect())?;
        println!("instance {:?} retained", remain_inst_ids);
        Ok(DeleteNetworkInstanceResponse {
            remain_inst_ids: remain_inst_ids.into_iter().map(Into::into).collect(),
        })
    }

    //   rpc GetConfig(GetConfigRequest) returns (GetConfigResponse) {}
    async fn get_config(
        &self,
        _: BaseController,
        req: GetConfigRequest,
    ) -> Result<GetConfigResponse, rpc_types::error::Error> {
        let inst_id = req.inst_id.ok_or_else(|| {
            rpc_types::error::Error::ExecutionError(
                anyhow::anyhow!("instance_id is required").into(),
            )
        })?;

        let config = self
            .manager
            .get_network_config(&inst_id.into())
            .ok_or_else(|| {
                rpc_types::error::Error::ExecutionError(
                    anyhow::anyhow!("instance {} not found", inst_id).into(),
                )
            })?;

        // Get the NetworkConfig from the instance
        let network_config = crate::launcher::NetworkConfig::new_from_config(&config)?;

        // Get the TOML config string
        let toml_config = config.dump();

        Ok(GetConfigResponse {
            config: Some(network_config),
            toml_config,
        })
    }

    //   rpc ReplaceConfig(ReplaceConfigRequest) returns (ReplaceConfigResponse) {}
    async fn replace_config(
        &self,
        _: BaseController,
        req: ReplaceConfigRequest,
    ) -> Result<ReplaceConfigResponse, rpc_types::error::Error> {
        let inst_id = req.inst_id.ok_or_else(|| {
            rpc_types::error::Error::ExecutionError(
                anyhow::anyhow!("instance_id is required").into(),
            )
        })?;

        let new_config = req.config.ok_or_else(|| {
            rpc_types::error::Error::ExecutionError(anyhow::anyhow!("config is required").into())
        })?;

        // Generate the TomlConfigLoader from NetworkConfig
        let new_toml_config = new_config.gen_config()?;

        // Replace the configuration
        match self
            .manager
            .replace_network_config(&inst_id.into(), new_toml_config)
        {
            Ok(()) => {
                println!("instance {} config replaced successfully", inst_id);
                Ok(ReplaceConfigResponse {
                    success: true,
                    error_msg: None,
                })
            }
            Err(e) => {
                let error_msg = format!("Failed to replace config for instance {}: {}", inst_id, e);
                eprintln!("{}", error_msg);
                Ok(ReplaceConfigResponse {
                    success: false,
                    error_msg: Some(error_msg),
                })
            }
        }
    }
}
