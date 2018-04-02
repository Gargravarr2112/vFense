class AppCollections():
    UniqueApplications = 'unique_applications'
    OsApps = 'os_apps'
    AppsPerAgent = 'apps_per_agent'
    CustomApps = 'custom_apps'
    CustomAppsPerAgent = 'custom_apps_per_agent'
    SupportedApps = 'supported_apps'
    SupportedAppsPerAgent = 'supported_apps_per_agent'
    vFenseApps = 'vfense_apps'
    vFenseAppsPerAgent = 'vfense_apps_per_agent'


class DownloadCollections():
    LatestDownloadedSupported = 'latest_downloaded_supported'
    LatestDownloadedAgent = 'latest_downloaded_agent'


class FileCollections():
    Files = 'files'
    FileServers = 'file_servers'


class FilesKeys():
    AppId = 'app_id'
    AppIds = 'app_ids'
    AgentIds = 'agent_ids'
    FileName = 'file_name'
    FileSize = 'file_size'
    FileUri = 'file_uri'
    FileHash = 'file_hash'
    FilesDownloadStatus = 'files_download_status'


class FilesIndexes():
    AppId = 'app_id'
    FilesDownloadStatus = 'files_download_status'


class FileServerKeys():
    FileServerName = 'file_server_name'
    Customers = 'customers'
    Address = 'address'


class FileServerIndexes():
    CustomerName = 'customer_name'

#-------------------------------------------------------

class DbCommonAppsKeys():
    AppId = 'app_id'
    Customers = 'customers'
    Name = 'name'
    Hidden = 'hidden'
    Description = 'description'
    ReleaseDate = 'release_date'
    RebootRequired = 'reboot_required'
    Kb = 'kb'
    FileSize = 'file_size'
    FileData = 'file_data'
    SupportUrl = 'support_url'
    Version = 'version'
    OsCode = 'os_code'
    RvSeverity = 'rv_severity'
    VendorSeverity = 'vendor_severity'
    VendorName = 'vendor_name'
    FilesDownloadStatus = 'files_download_status'
    VulnerabilityId = 'vulnerability_id'
    VulnerabilityCategories = 'vulnerability_categories'
    CveIds = 'cve_ids'
    CliOptions = 'cli_options'


class DbCommonAppsPerAgentKeys():
    AppId = 'app_id'
    Id = 'id'
    InstallDate = 'install_date'
    Status = 'status'
    Hidden = 'hidden'
    AgentId = 'agent_id'
    CustomerName = 'customer_name'
    Dependencies = 'dependencies'
    LastModifiedTime = 'last_modified_time'
    Update = 'update'
    CveIds = 'cve_ids'


class DbCommonAppsIndexes():
    AppId = 'app_id'
    Name = 'name'
    RvSeverity = 'rv_severity'
    AppIdAndRvSeverity = 'appid_and_rv_severity'
    NameAndVersion = 'name_and_version'
    Customers = 'customers'
    CustomerAndRvSeverity = 'customer_and_rvseverity'
    AppIdAndRvSeverityAndHidden = 'appid_and_rv_severity_and_hidden'
    AppIdAndHidden = 'appid_and_hidden'
    CustomerAndHidden = 'customer_and_hidden'


class DbCommonAppsPerAgentIndexes():
    AppId = 'app_id'
    AgentId = 'agent_id'
    Status = 'status'
    CustomerName = 'customer_name'
    AppIdAndStatus = 'appid_and_status'
    AgentIdAndAppId = 'agentid_and_appid'
    AppIdAndCustomer = 'appid_and_customer'
    StatusAndAgentId = 'status_and_agentid'
    AppIdStatusAndAgentId = 'appid_and_status_and_agentid'
    StatusAndCustomer = 'status_and_customer'
    StatusAndCveId = 'status_and_cve_id'
    AppIdAndStatusAndCustomer = 'appid_and_status_and_customer'

#--------------------------------------------------------------------    

class AppsKeys(DbCommonAppsKeys):
	pass #Now handled with inheritance


class AppsIndexes(DbCommonAppsIndexes):
	pass


class AppsPerAgentKeys(DbCommonAppsPerAgentKeys):
	pass


class AppsPerAgentIndexes(DbCommonAppsPerAgentIndexes):
	pass

#----------------------------------------------------------------------

class CustomAppsKeys(DbCommonAppsKeys):
	RvId = 'rv_id'
	CustomerName = 'customer_name'
	FilesVerified = 'files_verified'
	FilesDownloadStatus = 'files_download_status'
	MajorVersion = 'major_version'
	MinorVersion = 'minor_version'
	Arch = 'arch'


class CustomAppsIndexes(DbCommonAppsIndexes):
	pass


class CustomAppsPerAgentKeys(DbCommonAppsPerAgentKeys):
	Name = 'name'


class CustomAppsPerAgentIndexes(DbCommonAppsPerAgentIndexes):
	pass

#----------------------------------------------------------------------

class SupportedAppsKeys(CustomAppsKeys):
	pass


class SupportedAppsIndexes(DbCommonAppsIndexes):
	CustomerName = 'customer_name'


class SupportedAppsPerAgentKeys(CustomAppsPerAgentKeys):
	pass


class SupportedAppsPerAgentIndexes(DbCommonAppsPerAgentIndexes):
	pass

#----------------------------------------------------------------------

class AgentAppsKeys(CustomAppsKeys):
	pass


class AgentAppsIndexes(SupportedAppsIndexes):
	pass


class AgentAppsPerAgentKeys(CustomAppsPerAgentKeys):
    pass


class AgentAppsPerAgentIndexes(DbCommonAppsPerAgentIndexes):
	pass

#----------------------------------------------------------------------

class vFenseAppsKeys(CustomAppsKeys):
	pass


class vFenseAppsIndexes(SupportedAppsIndexes):
	pass


class vFenseAppsPerAgentKeys(CustomAppsPerAgentKeys):
	pass

class vFenseAppsPerAgentIndexes(DbCommonAppsPerAgentIndexes):
	pass

