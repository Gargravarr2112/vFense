class CommonAppKeys():
    CustomerName = 'customer_name'
    Id = 'id'
    APP_ID = 'app_id'
    APP_NAME = 'app_name'
    APP_VERSION = 'app_version'
    APP_URIS = 'app_uris'
    AGENTID = 'agent_id'
    COUNT = 'count'
    AGENT_COUNT = 'agent_count'
    AGENTS = 'agents'
    STATUS = 'status'
    NAME = 'name'
    VERSION = 'version'
    INSTALLED = 'installed'
    AVAILABLE = 'available'
    PENDING = 'pending'
    SOFTWAREINVENTORY = 'Software Inventory'
    OS = 'OS'
    CUSTOM = 'Custom'
    SUPPORTED = 'Supported'
    AGENT_UPDATES = 'Agent Updates'
    ValidPackageStatuses = (INSTALLED, AVAILABLE, PENDING)
    YES = 'yes'
    NO = 'no'
    ValidHiddenVals = (YES, NO)
    UPDATES = 'Updates'
    BASIC_RV_STATS = 'basic_rv_stats'

class CommonFileKeys():
    PKG_NAME = 'file_name'
    PKG_SIZE = 'file_size'
    PKG_URI = 'file_uri'
    FILE_URIS = 'file_uris'
    PKG_HASH = 'file_hash'
    PKG_URIS = 'uris'
    PKG_FILEDATA = 'file_data'
    PKG_CLI_OPTIONS = 'cli_options'

class CommonSeverityKeys():
    CRITICAL = 'Critical'
    OPTIONAL = 'Optional'
    RECOMMENDED = 'Recommended'
    ValidRvSeverities = (CRITICAL, RECOMMENDED, OPTIONAL)


class FileLocationUris():
    PACKAGES = 'packages'


class SharedAppKeys():
    AppId = 'app_id'
    Id = 'id'
    InstallDate = 'install_date'
    Status = 'status'
    Hidden = 'hidden'
    AgentId = 'agent_id'
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
    Dependencies = 'dependencies'
    LastModifiedTime = 'last_modified_time'
    Update = 'update'
