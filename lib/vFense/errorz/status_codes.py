class GenericCodes(object):
    InformationRetrieved = 1001
    CouldNotRetrieveInformation = 1002
    IncorrectArguments = 1003
    DoesNotExist = 1004
    CouldNotBeDeleted = 1005
    InvalidId = 1006
    InvalidFilter = 1007
    ObjectUpdated = 1008
    UpdateFailed = 1009
    ObjectCreated = 1010
    ObjectExists = 1011
    ObjectDeleted = 1012
    SomethingBroke = 1013
    FileUploaded = 1014
    FileFailedToUpload = 1015
    FileDoesNotExist = 1016
    ObjectUnchanged = 1017
    PermissionGranted = 1018
    PermissionDenied = 1019
    InvalidPermission = 1020
    AuthorizationGranted = 1021
    AuthorizationDenied = 1022
    MissingUsername = 1023
    MissingPassword = 1024


class GenericFailureCodes(object):
    FailedToCreateObject = 1500
    FailedToUpdateObject = 1501
    FailedToDeleteObject = 1502
    FailedToRetrieveObject = 1503
    DataIsEmpty = 1504
    InvalidSortKey = 1505
    InvalidFilterKey = 1506
    InvalidId = 1507
    InvalidPlugin = 1508

class GroupCodes(object):
    GroupCreated = 12000
    GroupUpdated = 12001
    GroupDeleted = 12002
    GroupUnchanged = 12003
    GroupsAddedToUser = 12004
    GroupsRemovedFromUser = 12005


class GroupFailureCodes(object):
    GroupIdExists = 12500
    InvalidPermissions = 12501
    FailedToRemoveGroup = 12502
    FailedToRemoveGroupFromUser = 12503
    FailedToCreateGroup = 12504
    FailedToAddGroupToUser = 12505
    FailedToUpdateGroup = 12506
    InvalidGroupName = 12507
    InvalidGroupId = 12508
    GroupExistForUser = 12509
    GroupDoesNotExistForUser = 12510
    CantRemoveAdminFromGroup = 12511
    UsersExistForGroup = 14512
    UsersDoNotExistForGroup = 14513


class UserCodes(object):
    UserCreated = 13000
    UserUpdated = 13001
    UserDeleted = 13002
    UserUnchanged = 13003
    PasswordChanged = 13004
    UsersAddedToCustomer = 13005
    UsersRemovedFromCustomer = 13006
    UsersAddedToGroup = 13007
    UsersRemovedFromGroup = 13008


class UserFailureCodes(object):
    UserNameExists = 13500
    UserNameDoesNotExist = 13501
    FailedToCreateUser = 13502
    FailedToRemoveUser = 13503
    FailedToUpdateUser = 13504
    InvalidUserName = 13505
    InvalidPassword = 13506
    WeakPassword = 13507
    NewPasswordSameAsOld = 13508
    AdminUserCanNotBeDeleted = 13509
    FailedToAddUsersToCustomer = 13510
    FailedToRemoveUsersFromCustomer = 13511
    CantDeleteAdminFromCustomer = 13512
    CantDeleteAdminUser = 13513
    FailedToAddUsersToGroup = 13514
    FailedToRemoveUsersFromGroup = 13515


class CustomerCodes(object):
    CustomerCreated = 14000
    CustomerUpdated = 14001
    CustomerDeleted = 14002
    CustomerUnchanged = 14003
    CustomersAddedToUser = 14004
    CustomersRemovedFromUser = 14005


class CustomerFailureCodes(object):
    CustomerExists = 14500
    CustomerDoesNotExist = 14501
    FailedToCreateCustomer = 14502
    FailedToRemoveCustomer = 14503
    FailedToRemoveUserFromCustomer = 14504
    FailedToUpdateCustomer = 14505
    InvalidCustomerName = 14506
    UsersExistForCustomer = 14507
    UsersDoNotExistForCustomer = 14508
    CantDeleteDefaultCustomer = 124509
    InvalidNetworkThrottle = 124509
    InvalidCpuThrottle = 124510
    InvalidOperationTTL = 124511


class DbCodes(object):
    Down = 2000
    Updated = 2001
    Inserted = 2002
    Unchanged = 2003
    Replaced = 2004
    Errors = 2005
    Deleted = 2006
    Nothing = 2007
    Skipped = 2008
    DoesNotExist = 2009


class AgentCodes(object):
    NewAgent = 3001
    NewAgentFailed = 3002
    CheckIn = 3003
    CheckInFailed = 3004
    Startup = 3005
    StartupFailed = 3006
    InstallUpdateResults = 3007
    InstallSupportedAppResults = 3008
    InstallCustomAppResults = 3009
    InstallAgentAppResults = 3010
    AgentsDeleted = 3011
    AgentsUpdated = 3012


class AgentResultCodes(object):
    NewAgentSucceeded = 3200
    CheckInSucceeded = 3201
    StartUpSucceeded = 3202
    ResultsUpdated = 3203


class AgentFailureResultCodes(object):
    NewAgentFailed = 3300
    CheckInFailed = 3301
    StartupFailed = 3302
    InvalidOperationId = 3303
    InvalidOperationIdWithAgentId = 3304
    ResultsFailedToUpdate = 3305
    InvalidSuccessValue = 3306


class AgentFailureCodes(object):
    AgentsFailedToDelete = 3500
    AgentsFailedToUpdate = 3501
    AgentsDoNotExist = 3502
    AgentsDoesNotExist = 3503
    AgentsExist = 3504


class TagCodes(object):
    TagCreatedAndAgentAdded = 4000
    RemovedAgentIdFromTag = 4001
    RemovedTagFromAgentId = 4002
    RemovedAllAgentsFromTag = 4003
    FailedToRemoveAllAgentsFromTag = 4004
    FailedToRemoveTag = 4005
    TagExistsAndAgentAdded = 4006


class PackageCodes(object):
    InvalidStatus = 5000
    InvalidPackageId = 5001
    InvalidFilter = 5002
    InvalidSeverity = 5003
    FileCompletedDownload = 5004
    FileIsDownloading = 5005
    FileNotRequired = 5006
    FilePendingDownload = 5007
    FileFailedDownload = 5008
    MissingUri = 5009
    InvalidUri = 5010
    HashNotVerified = 5011
    FileSizeMisMatch = 5012
    ThisIsNotAnUpdate = 5013
    ThisIsAnUpdate = 5014
    ToggleHiddenSuccessful = 5015
    AgentWillDownloadFromVendor = 5016
    PackageDeleted = 5017
    PackagesDeletionFailed = 5018


class PackageFailureCodes(object):
    ToggleHiddenFailed = 5300
    InvalidToggle = 5301
    ApplicationDoesNotExist = 5302


class AgentOperationCodes(object):
    Created = 6000
    Updated = 6001
    #Apps Results Codes For Operations
    ResultsReceived = 6002
    ResultsReceivedWithErrors = 6003
    ResultsPending = 6004
    InvalidOperationType = 6005
    #Results Codes For Operations
    ResultsCompleted = 6006
    ResultsCompletedWithErrors = 6007
    ResultsCompletedFailed = 6008
    ResultsIncomplete = 6009
    ResultsExpired = 6010
    OperationExpired = 6011


class AgentOperationFailureCodes(object):
    FailedToCreateOperation = 6200
    FailedToUpdateOperation = 6203


class OperationPerAgentCodes(object):
    Checkin = 6500
    PendingPickUp = 6501
    PickedUp = 6502
    OperationExpired = 6503
    OperationFailed = 6504
    OperationCompleted = 6505
    OperationCompletedWithErrors = 6506


class UpdatesApplications(object):
    UpdatesApplications = 7000
    UpdatesApplicationsFailed = 7001


class NotificationCodes(object):
    InvalidNotificationType = 8000
    InvalidNotificationPlugin = 8001
    InvalidNotificationThreshold = 8002
    NotificationDataValidated = 8003


class SchedulerCodes(object):
    ScheduleCreated = 9000
    ScheduleUpdated = 9001
    FailedToCreateSchedule = 9002
    InvalidTimeStamp = 9003
    InvalidScheduleType = 9004
    ScheduleRemoved = 9005
    ScheduleRemovedFailed = 9006
    InvalidScheduleName = 9007
    ScheduleExists = 9008


class MightyMouseCodes(object):
    MouseCreated = 10000
    MouseUpdated = 10001
    MouseRemoved = 10002
    FailedToAddMouse = 10003
    FailedToUpdateMouse = 10004
    FailedToRemoveMouse = 10005
    MouseExist = 10006
