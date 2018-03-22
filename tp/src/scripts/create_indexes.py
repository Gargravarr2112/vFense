#!/usr/bin/env python

from vFense.db.client import db_connect, r

from vFense.core.agent import *
from vFense.core.tag import *
from vFense.core.user import *
from vFense.core.group import *
from vFense.core.customer import *

from vFense.notifications import *
from vFense.operations import *
from vFense.plugins.patching import *
from vFense.plugins.mightymouse import *
from vFense.plugins.vuln.cve import *
from vFense.plugins.vuln.ubuntu import *
from vFense.plugins.vuln.windows import *
from vFense.core.queue import *

Id = 'id'
def initialize_indexes_and_create_tables():
    tables = [
        ('acls', Id),
        (AgentsCollection, AgentKeys.AgentId),
        (AppCollections.UniqueApplications, AppsKeys.AppId),
        (AppCollections.AppsPerAgent, Id),
        (AppCollections.CustomApps, CustomAppsKeys.AppId),
        (AppCollections.CustomAppsPerAgent, Id),
        (AppCollections.SupportedApps, SupportedAppsKeys.AppId),
        (AppCollections.SupportedAppsPerAgent, Id),
        (AppCollections.vFenseApps, vFenseAppsKeys.AppId),
        (AppCollections.vFenseAppsPerAgent, Id),
        (FileCollections.Files, FilesKeys.FileName),
        (FileCollections.FileServers, FileServerKeys.FileServerName),
        (CVECollections.CVE, CveKeys.CveId),
        (WindowsSecurityCollection.Bulletin, WindowsSecurityBulletinKeys.Id),
        (UbuntuSecurityCollection.Bulletin, UbuntuSecurityBulletinKeys.Id),
        ('downloaded_status', Id),
        (HardwarePerAgentCollection, Id),
        (NotificationCollections.NotificationPlugins, Id),
        (NotificationCollections.Notifications, NotificationKeys.NotificationId),
        (NotificationCollections.NotificationsHistory, Id),
        ('notification_queue', Id),
        (OperationCollections.Agent, AgentOperationKeys.OperationId),
        (OperationCollections.Admin, AgentOperationKeys.OperationId),
        (OperationCollections.OperationPerAgent, Id),
        (OperationCollections.OperationPerApp, Id),
        ('plugin_configurations', 'name'),
        (DownloadCollections.LatestDownloadedSupported, SupportedAppsKeys.AppId),
        (DownloadCollections.LatestDownloadedAgent, SupportedAppsKeys.AppId),
        (TagsCollection, TagsKeys.TagId),
        (TagsPerAgentCollection, Id),
        (QueueCollections.Agent, Id),
        (UserCollections.Users, UserKeys.UserName),
        (GroupCollections.Groups, GroupKeys.GroupId),
        (GroupCollections.GroupsPerUser, GroupsPerUserKeys.Id),
        (CustomerCollections.Customers, CustomerKeys.CustomerName),
        (CustomerCollections.CustomersPerUser, CustomerPerUserKeys.Id),
    ]
    conn = db_connect()
#################################### If Collections do not exist, create them #########################
    list_of_current_tables = r.table_list().run(conn)
    for table in tables:
        if table[0] not in list_of_current_tables:
            print "Creating table {0}".format(table[0])
            r.table_create(table[0], primary_key=table[1]).run(conn)

#################################### Get All Indexes ###################################################
    app_list = r.table(AppCollections.AppsPerAgent).index_list().run(conn)
    unique_app_list = r.table(AppCollections.UniqueApplications).index_list().run(conn)
    downloaded_list = r.table('downloaded_status').index_list().run(conn)
    custom_app_list = r.table(AppCollections.CustomApps).index_list().run(conn)
    custom_app_per_agent_list = r.table(AppCollections.CustomAppsPerAgent).index_list().run(conn)
    supported_app_list = r.table(AppCollections.SupportedApps).index_list().run(conn)
    supported_app_per_agent_list = r.table(AppCollections.SupportedAppsPerAgent).index_list().run(conn)
    vfense_app_list = r.table(AppCollections.vFenseApps).index_list().run(conn)
    vfense_app_per_agent_list = r.table(AppCollections.vFenseAppsPerAgent).index_list().run(conn)
    cve_list = r.table(CVECollections.CVE).index_list().run(conn)
    windows_bulletin_list = r.table(WindowsSecurityCollection.Bulletin).index_list().run(conn)
    ubuntu_bulletin_list = r.table(UbuntuSecurityCollection.Bulletin).index_list().run(conn)
    files_list = r.table(FileCollections.Files).index_list().run(conn)
    file_server_list = r.table(FileCollections.FileServers).index_list().run(conn)
    tags_list = r.table(TagsCollection).index_list().run(conn)
    agents_list = r.table(AgentsCollection).index_list().run(conn)
    agent_operations_list = r.table(OperationCollections.Agent).index_list().run(conn)
    admin_operations_list = r.table(OperationCollections.Admin).index_list().run(conn)
    operations_per_agent_list = r.table(OperationCollections.OperationPerAgent).index_list().run(conn)
    operations_per_app_list = r.table(OperationCollections.OperationPerApp).index_list().run(conn)
    notif_list = r.table(NotificationCollections.Notifications).index_list().run(conn)
    notif_history_list = r.table(NotificationCollections.NotificationsHistory).index_list().run(conn)
    hw_per_agent_list = r.table(HardwarePerAgentCollection).index_list().run(conn)
    tag_per_agent_list = r.table(TagsPerAgentCollection).index_list().run(conn)
    notif_plugin_list = r.table(NotificationCollections.NotificationPlugins,).index_list().run(conn)
    agent_queue_list = r.table(QueueCollections.Agent).index_list().run(conn)
    groups_list = r.table(GroupCollections.Groups).index_list().run(conn)
    groups_per_user_list = r.table(GroupCollections.GroupsPerUser).index_list().run(conn)
    customer_per_user_list = r.table(CustomerCollections.CustomersPerUser).index_list().run(conn)

#################################### AgentsColleciton Indexes ###################################################
    if not AgentIndexes.CustomerName in agents_list:
        print "Creating index {0}".format(AgentIndexes.CustomerName)
        r.table(AgentsCollection).index_create(AgentIndexes.CustomerName).run(conn)

    if not AgentIndexes.OsCode in agents_list:
        print "Creating index {0}".format(AgentIndexes.OsCode)
        r.table(AgentsCollection).index_create(AgentIndexes.OsCode).run(conn)

#################################### AppsCollection Indexes ###################################################
    if not AppsIndexes.RvSeverity in unique_app_list:
        print "Creating index {0}".format(AppsIndexes.RvSeverity)
        r.table(AppCollections.UniqueApplications).index_create(AppsIndexes.RvSeverity).run(conn)

    if not AppsIndexes.Name in unique_app_list:
        print "Creating index {0}".format(AppsIndexes.Name)
        r.table(AppCollections.UniqueApplications).index_create(AppsIndexes.Name).run(conn)

    if not AppsIndexes.NameAndVersion in unique_app_list:
        print "Creating index {0}".format(AppsIndexes.NameAndVersion)
        r.table(AppCollections.UniqueApplications).index_create(
            AppsIndexes.NameAndVersion, lambda x: [
                x[AppsKeys.Name], x[AppsKeys.Version]]).run(conn)

    if not AppsIndexes.Customers in unique_app_list:
        print "Creating index {0}".format(AppsIndexes.Customers)
        r.table(AppCollections.UniqueApplications).index_create(AppsIndexes.Customers, multi=True).run(conn)

    if not AppsIndexes.CustomerAndRvSeverity in unique_app_list:
        print "Creating index {0}".format(AppsIndexes.CustomerAndRvSeverity)
        r.table(AppCollections.UniqueApplications).index_create(
            AppsIndexes.CustomerAndRvSeverity, lambda x: [
                x[AppsKeys.Customers],
                x[AppsKeys.RvSeverity]], multi=True).run(conn)

    if not AppsIndexes.AppIdAndRvSeverity in unique_app_list:
        print "Creating index {0}".format(AppsIndexes.AppIdAndRvSeverity)
        r.table(AppCollections.UniqueApplications).index_create(
            AppsIndexes.AppIdAndRvSeverity, lambda x: [
                x[AppsKeys.AppId],
                x[AppsKeys.RvSeverity]]).run(conn)


#################################### FilesColleciton Indexes ###################################################
    if not FilesIndexes.FilesDownloadStatus in files_list:
        print "Creating index {0}".format(FilesIndexes.FilesDownloadStatus)
        r.table(FileCollections.Files).index_create(FilesIndexes.FilesDownloadStatus).run(conn)

#################################### AppsPerAgentCollection Indexes ###################################################
    if not AppsPerAgentIndexes.Status in app_list:
        print "Creating index {0}".format(AppsPerAgentIndexes.Status)
        r.table(AppCollections.AppsPerAgent).index_create(AppsPerAgentIndexes.Status).run(conn)

    if not AppsPerAgentIndexes.AgentId in app_list:
        print "Creating index {0}".format(AppsPerAgentIndexes.AgentId)
        r.table(AppCollections.AppsPerAgent).index_create(AppsPerAgentIndexes.AgentId).run(conn)

    if not AppsPerAgentIndexes.AppId in app_list:
        print "Creating index {0}".format(AppsPerAgentIndexes.AppId)
        r.table(AppCollections.AppsPerAgent).index_create(AppsPerAgentIndexes.AppId).run(conn)

    if not AppsPerAgentIndexes.CustomerName in app_list:
        print "Creating index {0}".format(AppsPerAgentIndexes.CustomerName)
        r.table(AppCollections.AppsPerAgent).index_create(AppsPerAgentIndexes.CustomerName).run(conn)

    if not AppsPerAgentIndexes.AgentIdAndAppId in app_list:
        print "Creating index {0}".format(AppsPerAgentIndexes.AgentIdAndAppId)
        r.table(AppCollections.AppsPerAgent).index_create(
            AppsPerAgentIndexes.AgentIdAndAppId, lambda x: [
                x[AppsPerAgentKeys.AgentId], x[AppsPerAgentKeys.AppId]]).run(conn)

    if not AppsPerAgentIndexes.AppIdAndCustomer in app_list:
        print "Creating index {0}".format(AppsPerAgentIndexes.AppIdAndCustomer)
        r.table(AppCollections.AppsPerAgent).index_create(
            AppsPerAgentIndexes.AppIdAndCustomer, lambda x: [
                x[AppsPerAgentKeys.AppId], x[AppsPerAgentKeys.CustomerName]]).run(conn)

    if not AppsPerAgentIndexes.AppIdAndStatus in app_list:
        print "Creating index {0}".format(AppsPerAgentIndexes.AppIdAndStatus)
        r.table(AppCollections.AppsPerAgent).index_create(
            AppsPerAgentIndexes.AppIdAndStatus, lambda x: [
                x[AppsPerAgentKeys.AppId], x[AppsPerAgentKeys.Status]]).run(conn)

    if not AppsPerAgentIndexes.StatusAndCustomer in app_list:
        print "Creating index {0}".format(AppsPerAgentIndexes.StatusAndCustomer)
        r.table(AppCollections.AppsPerAgent).index_create(
            AppsPerAgentIndexes.StatusAndCustomer, lambda x: [
                x[AppsPerAgentKeys.Status], x[AppsPerAgentKeys.CustomerName]]).run(conn)

    if not AppsPerAgentIndexes.AppIdAndStatusAndCustomer in app_list:
        print "Creating index {0}".format(AppsPerAgentIndexes.AppIdAndStatusAndCustomer)
        r.table(AppCollections.AppsPerAgent).index_create(
            AppsPerAgentIndexes.AppIdAndStatusAndCustomer, lambda x: [
                x[AppsPerAgentKeys.AppId],
                x[AppsPerAgentKeys.Status],
                x[AppsPerAgentKeys.CustomerName]]).run(conn)

    if not AppsPerAgentIndexes.StatusAndAgentId in app_list:
        print "Creating index {0}".format(AppsPerAgentIndexes.StatusAndAgentId)
        r.table(AppCollections.AppsPerAgent).index_create(
            AppsPerAgentIndexes.StatusAndAgentId, lambda x: [
                x[AppsPerAgentKeys.Status], x[AppsPerAgentKeys.AgentId]]).run(conn)


#################################### TagsCollection Indexes ###################################################
    if not TagsIndexes.CustomerName in tags_list:
        print "Creating index {0}".format(TagsIndexes.CustomerName)
        r.table(TagsCollection).index_create(TagsIndexes.CustomerName).run(conn)

    if not TagsIndexes.TagNameAndCustomer in tags_list:
        print "Creating index {0}".format(TagsIndexes.TagNameAndCustomer)
        r.table(TagsCollection).index_create(
            TagsIndexes.TagNameAndCustomer, lambda x: [
                x[TagsKeys.CustomerName], x[TagsKeys.TagName]]).run(conn)

#################################### TagsPerAgentCollection Indexes ###################################################
    if not TagsPerAgentIndexes.TagId in tag_per_agent_list:
        print "Creating index {0}".format(TagsPerAgentIndexes.TagId)
        r.table(TagsPerAgentCollection).index_create(TagsPerAgentIndexes.TagId).run(conn)

    if not TagsPerAgentIndexes.AgentId in tag_per_agent_list:
        print "Creating index {0}".format(TagsPerAgentIndexes.AgentId)
        r.table(TagsPerAgentCollection).index_create(TagsPerAgentIndexes.AgentId).run(conn)

    if not TagsPerAgentIndexes.AgentIdAndTagId in tag_per_agent_list:
        print "Creating index {0}".format(TagsPerAgentIndexes.AgentIdAndTagId)
        r.table(TagsPerAgentCollection).index_create(
            TagsPerAgentIndexes.AgentIdAndTagId, lambda x: [
                x[TagsPerAgentKeys.AgentId],
                x[TagsPerAgentKeys.TagId]]).run(conn)


#################################### CustomAppsCollection Indexes ###################################################
    if not CustomAppsIndexes.RvSeverity in custom_app_list:
        print "Creating index {0}".format(CustomAppsIndexes.RvSeverity)
        r.table(AppCollections.CustomApps).index_create(CustomAppsIndexes.RvSeverity).run(conn)

    if not CustomAppsIndexes.Name in custom_app_list:
        print "Creating index {0}".format(CustomAppsIndexes.Name)
        r.table(AppCollections.CustomApps).index_create(CustomAppsIndexes.Name).run(conn)

    if not CustomAppsIndexes.NameAndVersion in custom_app_list:
        print "Creating index {0}".format(CustomAppsIndexes.NameAndVersion)
        r.table(AppCollections.CustomApps).index_create(
            CustomAppsIndexes.NameAndVersion, lambda x: [
                x[CustomAppsKeys.Name], x[CustomAppsKeys.Version]]).run(conn)

    if not CustomAppsIndexes.Customers in custom_app_list:
        print "Creating index {0}".format(CustomAppsIndexes.Customers)
        r.table(AppCollections.CustomApps).index_create(CustomAppsIndexes.Customers, multi=True).run(conn)

    if not CustomAppsIndexes.CustomerAndRvSeverity in custom_app_list:
        print "Creating index {0}".format(CustomAppsIndexes.CustomerAndRvSeverity)
        r.table(AppCollections.CustomApps).index_create(
            CustomAppsIndexes.CustomerAndRvSeverity, lambda x: [
                x[CustomAppsKeys.Customers], x[CustomAppsKeys.RvSeverity]], multi=True).run(conn)

    if not CustomAppsIndexes.AppIdAndRvSeverity in custom_app_list:
        print "Creating index {0}".format(CustomAppsIndexes.AppIdAndRvSeverity)
        r.table(AppCollections.CustomApps).index_create(
            CustomAppsIndexes.AppIdAndRvSeverity, lambda x: [
                x[CustomAppsKeys.AppId],
                x[CustomAppsKeys.RvSeverity]]).run(conn)

#################################### CustomAppsPerAgentCollection Indexes ###################################################
    if not CustomAppsPerAgentIndexes.Status in custom_app_per_agent_list:
        print "Creating index {0}".format(CustomAppsPerAgentIndexes.Status)
        r.table(AppCollections.CustomAppsPerAgent).index_create(CustomAppsPerAgentIndexes.Status).run(conn)

    if not CustomAppsPerAgentIndexes.AgentId in custom_app_per_agent_list:
        print "Creating index {0}".format(CustomAppsPerAgentIndexes.AgentId)
        r.table(AppCollections.CustomAppsPerAgent).index_create(CustomAppsPerAgentIndexes.AgentId).run(conn)

    if not CustomAppsPerAgentIndexes.AppId in custom_app_per_agent_list:
        print "Creating index {0}".format(CustomAppsPerAgentIndexes.AppId)
        r.table(AppCollections.CustomAppsPerAgent).index_create(CustomAppsPerAgentIndexes.AppId).run(conn)

    if not CustomAppsPerAgentIndexes.CustomerName in custom_app_per_agent_list:
        print "Creating index {0}".format(CustomAppsPerAgentIndexes.CustomerName)
        r.table(AppCollections.CustomAppsPerAgent).index_create(CustomAppsPerAgentIndexes.CustomerName).run(conn)

    if not CustomAppsPerAgentIndexes.AgentIdAndAppId in custom_app_per_agent_list:
        print "Creating index {0}".format(CustomAppsPerAgentIndexes.AgentIdAndAppId)
        r.table(AppCollections.CustomAppsPerAgent).index_create(
            CustomAppsPerAgentIndexes.AgentIdAndAppId, lambda x: [
                x[CustomAppsPerAgentKeys.AgentId], x[CustomAppsPerAgentKeys.AppId]]).run(conn)

    if not CustomAppsPerAgentIndexes.AppIdAndCustomer in custom_app_per_agent_list:
        print "Creating index {0}".format(CustomAppsPerAgentIndexes.AppIdAndCustomer)
        r.table(AppCollections.CustomAppsPerAgent).index_create(
            CustomAppsPerAgentIndexes.AppIdAndCustomer, lambda x: [
                x[CustomAppsPerAgentKeys.AppId], x[CustomAppsPerAgentKeys.CustomerName]]).run(conn)

    if not CustomAppsPerAgentIndexes.AppIdAndStatus in custom_app_per_agent_list:
        print "Creating index {0}".format(CustomAppsPerAgentIndexes.AppIdAndStatus)
        r.table(AppCollections.CustomAppsPerAgent).index_create(
            CustomAppsPerAgentIndexes.AppIdAndStatus, lambda x: [
                x[CustomAppsPerAgentKeys.AppId], x[CustomAppsPerAgentKeys.Status]]).run(conn)

    if not CustomAppsPerAgentIndexes.StatusAndCustomer in custom_app_per_agent_list:
        print "Creating index {0}".format(CustomAppsPerAgentIndexes.StatusAndCustomer)
        r.table(AppCollections.CustomAppsPerAgent).index_create(
            CustomAppsPerAgentIndexes.StatusAndCustomer, lambda x: [
                x[CustomAppsPerAgentKeys.Status], x[CustomAppsPerAgentKeys.CustomerName]]).run(conn)

    if not CustomAppsPerAgentIndexes.AppIdAndStatusAndCustomer in custom_app_per_agent_list:
        print "Creating index {0}".format(CustomAppsPerAgentIndexes.AppIdAndStatusAndCustomer)
        r.table(AppCollections.CustomAppsPerAgent).index_create(
            CustomAppsPerAgentIndexes.AppIdAndStatusAndCustomer, lambda x: [
                x[CustomAppsPerAgentKeys.AppId],
                x[CustomAppsPerAgentKeys.Status],
                x[CustomAppsPerAgentKeys.CustomerName]]).run(conn)

    if not CustomAppsPerAgentIndexes.StatusAndAgentId in custom_app_per_agent_list:
        print "Creating index {0}".format(CustomAppsPerAgentIndexes.StatusAndAgentId)
        r.table(AppCollections.CustomAppsPerAgent).index_create(
            CustomAppsPerAgentIndexes.StatusAndAgentId, lambda x: [
                x[CustomAppsPerAgentKeys.Status], x[CustomAppsPerAgentKeys.AgentId]]).run(conn)

#################################### SupportedAppsCollection Indexes ###################################################
    if not SupportedAppsIndexes.RvSeverity in supported_app_list:
        print "Creating index {0}".format(SupportedAppsIndexes.RvSeverity)
        r.table(AppCollections.SupportedApps).index_create(SupportedAppsIndexes.RvSeverity).run(conn)

    if not SupportedAppsIndexes.Name in supported_app_list:
        print "Creating index {0}".format(SupportedAppsIndexes.Name)
        r.table(AppCollections.SupportedApps).index_create(SupportedAppsIndexes.Name).run(conn)

    if not SupportedAppsIndexes.NameAndVersion in supported_app_list:
        print "Creating index {0}".format(SupportedAppsIndexes.NameAndVersion)
        r.table(AppCollections.SupportedApps).index_create(
            SupportedAppsIndexes.NameAndVersion, lambda x: [
                x[SupportedAppsKeys.Name], x[SupportedAppsKeys.Version]]).run(conn)

    if not SupportedAppsIndexes.Customers in supported_app_list:
        print "Creating index {0}".format(SupportedAppsIndexes.Customers)
        r.table(AppCollections.SupportedApps).index_create(SupportedAppsIndexes.Customers, multi=True).run(conn)

    if not SupportedAppsIndexes.CustomerAndRvSeverity in supported_app_list:
        print "Creating index {0}".format(SupportedAppsIndexes.CustomerAndRvSeverity)
        r.table(AppCollections.SupportedApps).index_create(
            SupportedAppsIndexes.CustomerAndRvSeverity, lambda x: [
                x[SupportedAppsKeys.Customers], x[SupportedAppsKeys.RvSeverity]], multi=True).run(conn)

    if not SupportedAppsIndexes.AppIdAndRvSeverity in supported_app_list:
        print "Creating index {0}".format(SupportedAppsIndexes.AppIdAndRvSeverity)
        r.table(AppCollections.SupportedApps).index_create(
            SupportedAppsIndexes.AppIdAndRvSeverity, lambda x: [
                x[SupportedAppsKeys.AppId],
                x[SupportedAppsKeys.RvSeverity]]).run(conn)

#################################### SupportedAppsPerAgentCollection Indexes ###################################################
    if not SupportedAppsPerAgentIndexes.Status in supported_app_per_agent_list:
        print "Creating index {0}".format(SupportedAppsPerAgentIndexes.Status)
        r.table(AppCollections.SupportedAppsPerAgent).index_create(SupportedAppsPerAgentIndexes.Status).run(conn)

    if not SupportedAppsPerAgentIndexes.AgentId in supported_app_per_agent_list:
        print "Creating index {0}".format(SupportedAppsPerAgentIndexes.AgentId)
        r.table(AppCollections.SupportedAppsPerAgent).index_create(SupportedAppsPerAgentIndexes.AgentId).run(conn)

    if not SupportedAppsPerAgentIndexes.AppId in supported_app_per_agent_list:
        print "Creating index {0}".format(SupportedAppsPerAgentIndexes.AppId)
        r.table(AppCollections.SupportedAppsPerAgent).index_create(SupportedAppsPerAgentIndexes.AppId).run(conn)

    if not SupportedAppsPerAgentIndexes.CustomerName in supported_app_per_agent_list:
        print "Creating index {0}".format(SupportedAppsPerAgentIndexes.CustomerName)
        r.table(AppCollections.SupportedAppsPerAgent).index_create(SupportedAppsPerAgentIndexes.CustomerName).run(conn)

    if not SupportedAppsPerAgentIndexes.AgentIdAndAppId in supported_app_per_agent_list:
        print "Creating index {0}".format(SupportedAppsPerAgentIndexes.AgentIdAndAppId)
        r.table(AppCollections.SupportedAppsPerAgent).index_create(
            SupportedAppsPerAgentIndexes.AgentIdAndAppId, lambda x: [
                x[SupportedAppsPerAgentKeys.AgentId], x[SupportedAppsPerAgentKeys.AppId]]).run(conn)

    if not SupportedAppsPerAgentIndexes.AppIdAndCustomer in supported_app_per_agent_list:
        print "Creating index {0}".format(SupportedAppsPerAgentIndexes.AppIdAndCustomer)
        r.table(AppCollections.SupportedAppsPerAgent).index_create(
            SupportedAppsPerAgentIndexes.AppIdAndCustomer, lambda x: [
                x[SupportedAppsPerAgentKeys.AppId], x[SupportedAppsPerAgentKeys.CustomerName]]).run(conn)

    if not SupportedAppsPerAgentIndexes.AppIdAndStatus in supported_app_per_agent_list:
        print "Creating index {0}".format(SupportedAppsPerAgentIndexes.AppIdAndStatus)
        r.table(AppCollections.SupportedAppsPerAgent).index_create(
            SupportedAppsPerAgentIndexes.AppIdAndStatus, lambda x: [
                x[SupportedAppsPerAgentKeys.AppId], x[SupportedAppsPerAgentKeys.Status]]).run(conn)

    if not SupportedAppsPerAgentIndexes.StatusAndCustomer in supported_app_per_agent_list:
        print "Creating index {0}".format(SupportedAppsPerAgentIndexes.StatusAndCustomer)
        r.table(AppCollections.SupportedAppsPerAgent).index_create(
            SupportedAppsPerAgentIndexes.StatusAndCustomer, lambda x: [
                x[SupportedAppsPerAgentKeys.Status], x[SupportedAppsPerAgentKeys.CustomerName]]).run(conn)

    if not SupportedAppsPerAgentIndexes.AppIdAndStatusAndCustomer in supported_app_per_agent_list:
        print "Creating index {0}".format(SupportedAppsPerAgentIndexes.AppIdAndStatusAndCustomer)
        r.table(AppCollections.SupportedAppsPerAgent).index_create(
            SupportedAppsPerAgentIndexes.AppIdAndStatusAndCustomer, lambda x: [
                x[SupportedAppsPerAgentKeys.AppId],
                x[SupportedAppsPerAgentKeys.Status],
                x[SupportedAppsPerAgentKeys.CustomerName]]).run(conn)

    if not SupportedAppsPerAgentIndexes.StatusAndAgentId in supported_app_per_agent_list:
        print "Creating index {0}".format(SupportedAppsPerAgentIndexes.StatusAndAgentId)
        r.table(AppCollections.SupportedAppsPerAgent).index_create(
            SupportedAppsPerAgentIndexes.StatusAndAgentId, lambda x: [
                x[SupportedAppsPerAgentKeys.Status], x[SupportedAppsPerAgentKeys.AgentId]]).run(conn)

#################################### vFenseAppsCollection Indexes ###################################################
    if not vFenseAppsIndexes.RvSeverity in vfense_app_list:
        print "Creating index {0}".format(vFenseAppsIndexes.RvSeverity)
        r.table(AppCollections.vFenseApps).index_create(AgentAppsIndexes.RvSeverity).run(conn)

    if not vFenseAppsIndexes.Name in vfense_app_list:
        print "Creating index {0}".format(vFenseAppsIndexes.Name)
        r.table(AppCollections.vFenseApps).index_create(AgentAppsIndexes.Name).run(conn)

    if not vFenseAppsIndexes.NameAndVersion in vfense_app_list:
        print "Creating index {0}".format(vFenseAppsIndexes.NameAndVersion)
        r.table(AppCollections.vFenseApps).index_create(
            vFenseAppsIndexes.NameAndVersion, lambda x: [
                x[vFenseAppsKeys.Name], x[vFenseAppsKeys.Version]]).run(conn)

    if not vFenseAppsIndexes.Customers in vfense_app_list:
        print "Creating index {0}".format(vFenseAppsIndexes.Customers)
        r.table(AppCollections.vFenseApps).index_create(AgentAppsIndexes.Customers, multi=True).run(conn)

    if not vFenseAppsIndexes.CustomerAndRvSeverity in vfense_app_list:
        print "Creating index {0}".format(vFenseAppsIndexes.CustomerAndRvSeverity)
        r.table(AppCollections.vFenseApps).index_create(
            vFenseAppsIndexes.CustomerAndRvSeverity, lambda x: [
                x[vFenseAppsKeys.Customers], x[vFenseAppsKeys.RvSeverity]], multi=True).run(conn)

    if not vFenseAppsIndexes.AppIdAndRvSeverity in vfense_app_list:
        print "Creating index {0}".format(vFenseAppsIndexes.AppIdAndRvSeverity)
        r.table(AppCollections.vFenseApps).index_create(
            vFenseAppsIndexes.AppIdAndRvSeverity, lambda x: [
                x[vFenseAppsKeys.AppId],
                x[vFenseAppsKeys.RvSeverity]]).run(conn)

#################################### vFenseAppsPerAgentCollection Indexes ###################################################
    if not vFenseAppsPerAgentIndexes.Status in vfense_app_per_agent_list:
        print "Creating index {0}".format(vFenseAppsPerAgentIndexes.Status)
        r.table(AppCollections.vFenseAppsPerAgent).index_create(AgentAppsPerAgentIndexes.Status).run(conn)

    if not vFenseAppsPerAgentIndexes.AgentId in vfense_app_per_agent_list:
        print "Creating index {0}".format(vFenseAppsPerAgentIndexes.AgentId)
        r.table(AppCollections.vFenseAppsPerAgent).index_create(AgentAppsPerAgentIndexes.AgentId).run(conn)

    if not vFenseAppsPerAgentIndexes.AppId in vfense_app_per_agent_list:
        print "Creating index {0}".format(vFenseAppsPerAgentIndexes.AppId)
        r.table(AppCollections.vFenseAppsPerAgent).index_create(AgentAppsPerAgentIndexes.AppId).run(conn)

    if not vFenseAppsPerAgentIndexes.CustomerName in vfense_app_per_agent_list:
        print "Creating index {0}".format(vFenseAppsPerAgentIndexes.CustomerName)
        r.table(AppCollections.vFenseAppsPerAgent).index_create(AgentAppsPerAgentIndexes.CustomerName).run(conn)

    if not vFenseAppsPerAgentIndexes.AgentIdAndAppId in vfense_app_per_agent_list:
        print "Creating index {0}".format(vFenseAppsPerAgentIndexes.AgentIdAndAppId)
        r.table(AppCollections.vFenseAppsPerAgent).index_create(
            vFenseAppsPerAgentIndexes.AgentIdAndAppId, lambda x: [
                x[vFenseAppsPerAgentKeys.AgentId], x[vFenseAppsPerAgentKeys.AppId]]).run(conn)

    if not vFenseAppsPerAgentIndexes.AppIdAndCustomer in vfense_app_per_agent_list:
        print "Creating index {0}".format(vFenseAppsPerAgentIndexes.AppIdAndCustomer)
        r.table(AppCollections.vFenseAppsPerAgent).index_create(
            vFenseAppsPerAgentIndexes.AppIdAndCustomer, lambda x: [
                x[vFenseAppsPerAgentKeys.AppId], x[vFenseAppsPerAgentKeys.CustomerName]]).run(conn)

    if not vFenseAppsPerAgentIndexes.AppIdAndStatus in vfense_app_per_agent_list:
        print "Creating index {0}".format(vFenseAppsPerAgentIndexes.AppIdAndStatus)
        r.table(AppCollections.vFenseAppsPerAgent).index_create(
            vFenseAppsPerAgentIndexes.AppIdAndStatus, lambda x: [
                x[vFenseAppsPerAgentKeys.AppId], x[vFenseAppsPerAgentKeys.Status]]).run(conn)

    if not vFenseAppsPerAgentIndexes.StatusAndCustomer in vfense_app_per_agent_list:
        print "Creating index {0}".format(vFenseAppsPerAgentIndexes.StatusAndCustomer)
        r.table(AppCollections.vFenseAppsPerAgent).index_create(
            vFenseAppsPerAgentIndexes.StatusAndCustomer, lambda x: [
                x[vFenseAppsPerAgentKeys.Status], x[vFenseAppsPerAgentKeys.CustomerName]]).run(conn)

    if not vFenseAppsPerAgentIndexes.AppIdAndStatusAndCustomer in vfense_app_per_agent_list:
        print "Creating index {0}".format(vFenseAppsPerAgentIndexes.AppIdAndStatusAndCustomer)
        r.table(AppCollections.vFenseAppsPerAgent).index_create(
            vFenseAppsPerAgentIndexes.AppIdAndStatusAndCustomer, lambda x: [
                x[vFenseAppsPerAgentKeys.AppId],
                x[vFenseAppsPerAgentKeys.Status],
                x[vFenseAppsPerAgentKeys.CustomerName]]).run(conn)

    if not vFenseAppsPerAgentIndexes.StatusAndAgentId in vfense_app_per_agent_list:
        print "Creating index {0}".format(vFenseAppsPerAgentIndexes.StatusAndAgentId)
        r.table(AppCollections.vFenseAppsPerAgent).index_create(
            vFenseAppsPerAgentIndexes.StatusAndAgentId, lambda x: [
                x[vFenseAppsPerAgentKeys.Status], x[vFenseAppsPerAgentKeys.AgentId]]).run(conn)


#################################### AgentOperationsCollection Indexes ###################################################
    if not AgentOperationIndexes.CustomerName in agent_operations_list:
        print "Creating index {0}".format(AgentOperationIndexes.CustomerName)
        r.table(OperationCollections.Agent).index_create(AgentOperationKeys.CustomerName).run(conn)

    if not AgentOperationIndexes.TagId in agent_operations_list:
        print "Creating index {0}".format(AgentOperationIndexes.TagId)
        r.table(OperationCollections.Agent).index_create(AgentOperationKeys.TagId).run(conn)

    if not AgentOperationIndexes.Operation in agent_operations_list:
        print "Creating index {0}".format(AgentOperationIndexes.Operation)
        r.table(OperationCollections.Agent).index_create(AgentOperationKeys.Operation).run(conn)

    if not AgentOperationIndexes.AgentIds in agent_operations_list:
        print "Creating index {0}".format(AgentOperationIndexes.AgentIds)
        r.table(OperationCollections.Agent).index_create(AgentOperationIndexes.AgentIds, multi=True).run(conn)

    if not AgentOperationIndexes.OperationAndCustomer in agent_operations_list:
        print "Creating index {0}".format(AgentOperationIndexes.OperationAndCustomer)
        r.table(OperationCollections.Agent).index_create(
            AgentOperationIndexes.OperationAndCustomer, lambda x: [
                x[AgentOperationKeys.Operation],
                x[AgentOperationKeys.CustomerName]]).run(conn)

    if not AgentOperationIndexes.PluginAndCustomer in agent_operations_list:
        print "Creating index {0}".format(AgentOperationIndexes.PluginAndCustomer)
        r.table(OperationCollections.Agent).index_create(
            AgentOperationIndexes.PluginAndCustomer, lambda x: [
                x[AgentOperationKeys.Plugin],
                x[AgentOperationKeys.CustomerName]]).run(conn)

    if not AgentOperationIndexes.CreatedByAndCustomer in agent_operations_list:
        print "Creating index {0}".format(AgentOperationIndexes.CreatedByAndCustomer)
        r.table(OperationCollections.Agent).index_create(
            AgentOperationIndexes.CreatedByAndCustomer, lambda x: [
                x[AgentOperationKeys.CreatedBy],
                x[AgentOperationKeys.CustomerName]]).run(conn)

#################################### OperationsPerAgentCollection Indexes ###################################################
    if not OperationPerAgentIndexes.OperationId in operations_per_agent_list:
        print "Creating index {0}".format(OperationPerAgentIndexes.OperationId)
        r.table(OperationCollections.OperationPerAgent).index_create(OperationPerAgentKeys.OperationId).run(conn)

    if not OperationPerAgentIndexes.AgentIdAndCustomer in operations_per_agent_list:
        print "Creating index {0}".format(OperationPerAgentIndexes.AgentIdAndCustomer)
        r.table(OperationCollections.OperationPerAgent).index_create(
            OperationPerAgentIndexes.AgentIdAndCustomer, lambda x: [
                x[OperationPerAgentKeys.AgentId],
                x[OperationPerAgentKeys.CustomerName]]).run(conn)

    if not OperationPerAgentIndexes.TagIdAndCustomer in operations_per_agent_list:
        print "Creating index {0}".format(OperationPerAgentIndexes.TagIdAndCustomer)
        r.table(OperationCollections.OperationPerAgent).index_create(
            OperationPerAgentIndexes.TagIdAndCustomer, lambda x: [
                x[OperationPerAgentKeys.TagId],
                x[OperationPerAgentKeys.CustomerName]]).run(conn)

    if not OperationPerAgentIndexes.StatusAndCustomer in operations_per_agent_list:
        print "Creating index {0}".format(OperationPerAgentIndexes.StatusAndCustomer)
        r.table(OperationCollections.OperationPerAgent).index_create(
            OperationPerAgentIndexes.StatusAndCustomer, lambda x: [
                x[OperationPerAgentKeys.Status],
                x[OperationPerAgentKeys.CustomerName]]).run(conn)

    if not OperationPerAgentIndexes.OperationIdAndAgentId in operations_per_agent_list:
        print "Creating index {0}".format(OperationPerAgentIndexes.OperationIdAndAgentId)
        r.table(OperationCollections.OperationPerAgent).index_create(
            OperationPerAgentIndexes.OperationIdAndAgentId, lambda x: [
                x[OperationPerAgentKeys.OperationId],
                x[OperationPerAgentKeys.AgentId]]).run(conn)

#################################### OperationsPerAppCollection Indexes ###################################################
    if not OperationPerAppIndexes.OperationId in operations_per_app_list:
        print "Creating index {0}".format(OperationPerAppIndexes.OperationId)
        r.table(OperationCollections.OperationPerApp).index_create(OperationPerAppKeys.OperationId).run(conn)

    if not OperationPerAppIndexes.OperationIdAndAgentId in operations_per_app_list:
        print "Creating index {0}".format(OperationPerAppIndexes.OperationIdAndAgentId)
        r.table(OperationCollections.OperationPerApp).index_create(
            OperationPerAppIndexes.OperationIdAndAgentId, lambda x: [
                x[OperationPerAppKeys.OperationId],
                x[OperationPerAppKeys.AgentId]]).run(conn)

    if not OperationPerAppIndexes.OperationIdAndAgentIdAndAppId in operations_per_app_list:
        print "Creating index {0}".format(OperationPerAppIndexes.OperationIdAndAgentIdAndAppId)
        r.table(OperationCollections.OperationPerApp).index_create(
            OperationPerAppIndexes.OperationIdAndAgentIdAndAppId, lambda x: [
                x[OperationPerAppKeys.OperationId],
                x[OperationPerAppKeys.AgentId],
                x[OperationPerAppKeys.AppId]]).run(conn)

#################################### HardwarePerAgentCollection Indexes ###################################################
    if not HardwarePerAgentIndexes.Type in hw_per_agent_list:
        print "Creating index {0}".format(HardwarePerAgentIndexes.Type)
        r.table(HardwarePerAgentCollection).index_create(HardwarePerAgentIndexes.Type).run(conn)

    if not HardwarePerAgentIndexes.AgentId in hw_per_agent_list:
        print "Creating index {0}".format(HardwarePerAgentIndexes.AgentId)
        r.table(HardwarePerAgentCollection).index_create(HardwarePerAgentIndexes.AgentId).run(conn)

#################################### DownloadStatusCollection Indexes ###################################################
    if not 'app_id' in downloaded_list:
        r.table('downloaded_status').index_create('app_id').run(conn)

    if not 'by_filename_and_rvid' in downloaded_list:
        r.table('downloaded_status').index_create(
            'by_filename_and_rvid', lambda x: [
                x['file_name'], x['app_id']]).run(conn)

#################################### NotificationsCollection Indexes ###################################################
    if not NotificationIndexes.CustomerName in notif_list:
        print "Creating index {0}".format(NotificationIndexes.CustomerName)
        r.table(NotificationCollections.Notifications).index_create(NotificationKeys.CustomerName).run(conn)

    if not NotificationIndexes.RuleNameAndCustomer in notif_list:
        print "Creating index {0}".format(NotificationIndexes.RuleNameAndCustomer)
        r.table(NotificationCollections.Notifications).index_create(
            NotificationIndexes.RuleNameAndCustomer, lambda x: [
                x[NotificationKeys.RuleName],
                x[NotificationKeys.CustomerName]]).run(conn)

    if not NotificationIndexes.NotificationTypeAndCustomer in notif_list:
        print "Creating index {0}".format(NotificationIndexes.NotificationTypeAndCustomer)
        r.table(NotificationCollections.Notifications).index_create(
            NotificationIndexes.NotificationTypeAndCustomer, lambda x: [
                x[NotificationKeys.NotificationType],
                x[NotificationKeys.CustomerName]]).run(conn)

    if not NotificationIndexes.AppThresholdAndCustomer in notif_list:
        print "Creating index {0}".format(NotificationIndexes.AppThresholdAndCustomer)
        r.table(NotificationCollections.Notifications).index_create(
            NotificationIndexes.AppThresholdAndCustomer, lambda x: [
                x[NotificationKeys.AppThreshold],
                x[NotificationKeys.CustomerName]]).run(conn)

    if not NotificationIndexes.RebootThresholdAndCustomer in notif_list:
        print "Creating index {0}".format(NotificationIndexes.RebootThresholdAndCustomer)
        r.table(NotificationCollections.Notifications).index_create(
            NotificationIndexes.RebootThresholdAndCustomer, lambda x: [
                x[NotificationKeys.RebootThreshold],
                x[NotificationKeys.CustomerName]]).run(conn)

    if not NotificationIndexes.ShutdownThresholdAndCustomer in notif_list:
        print "Creating index {0}".format(NotificationIndexes.ShutdownThresholdAndCustomer)
        r.table(NotificationCollections.Notifications).index_create(
            NotificationIndexes.ShutdownThresholdAndCustomer, lambda x: [
                x[NotificationKeys.ShutdownThreshold],
                x[NotificationKeys.CustomerName]]).run(conn)

    if not NotificationIndexes.CpuThresholdAndCustomer in notif_list:
        print "Creating index {0}".format(NotificationIndexes.CpuThresholdAndCustomer)
        r.table(NotificationCollections.Notifications).index_create(
            NotificationIndexes.CpuThresholdAndCustomer, lambda x: [
                x[NotificationKeys.CpuThreshold],
                x[NotificationKeys.CustomerName]]).run(conn)

    if not NotificationIndexes.MemThresholdAndCustomer in notif_list:
        print "Creating index {0}".format(NotificationIndexes.MemThresholdAndCustomer)
        r.table(NotificationCollections.Notifications).index_create(
            NotificationIndexes.MemThresholdAndCustomer, lambda x: [
                x[NotificationKeys.MemThreshold],
                x[NotificationKeys.CustomerName]]).run(conn)

    if not NotificationIndexes.FileSystemThresholdAndFileSystemAndCustomer in notif_list:
        print "Creating index {0}".format(NotificationIndexes.FileSystemThresholdAndFileSystemAndCustomer)
        r.table(NotificationCollections.Notifications).index_create(
            NotificationIndexes.FileSystemThresholdAndFileSystemAndCustomer, lambda x: [
                x[NotificationKeys.FileSystemThreshold],
                x[NotificationKeys.FileSystem],
                x[NotificationKeys.CustomerName]]).run(conn)

#################################### NotificationsHistory Indexes ###################################################
    if not NotificationHistoryIndexes.NotificationId in notif_history_list:
        print "Creating index {0}".format(NotificationHistoryIndexes.NotificationId)
        r.table(NotificationCollections.NotificationsHistory).index_create(NotificationHistoryKeys.NotificationId).run(conn)

#################################### NotificationsPlugin Indexes ###################################################
    if not NotificationPluginIndexes.CustomerName in notif_plugin_list:
        print "Creating index {0}".format(NotificationPluginIndexes.CustomerName)
        r.table(NotificationCollections.NotificationPlugins).index_create(NotificationPluginKeys.CustomerName).run(conn)

#################################### Cve Indexes ###################################################
    if not CveIndexes.CveCategories in cve_list:
        print "Creating index {0}".format(CveIndexes.CveCategories)
        r.table(CVECollections.CVE).index_create(CveIndexes.CveCategories, multi=True).run(conn)

#################################### Windows Bulletin Indexes ###################################################
    if not WindowsSecurityBulletinIndexes.BulletinId in windows_bulletin_list:
        print "Creating index {0}".format(WindowsSecurityBulletinIndexes.BulletinId)
        r.table(WindowsSecurityCollection.Bulletin).index_create(WindowsSecurityBulletinIndexes.BulletinId).run(conn)

    if not WindowsSecurityBulletinIndexes.ComponentKb in windows_bulletin_list:
        print "Creating index {0}".format(WindowsSecurityBulletinIndexes.ComponentKb)
        r.table(WindowsSecurityCollection.Bulletin).index_create(WindowsSecurityBulletinIndexes.ComponentKb).run(conn)

    if not WindowsSecurityBulletinIndexes.CveIds in windows_bulletin_list:
        print "Creating index {0}".format(WindowsSecurityBulletinIndexes.CveIds)
        r.table(WindowsSecurityCollection.Bulletin).index_create(WindowsSecurityBulletinIndexes.CveIds, multi=True).run(conn)
#################################### Ubuntu Bulletin Indexes ###################################################
    if not UbuntuSecurityBulletinIndexes.BulletinId in ubuntu_bulletin_list:
        print "Creating index {0}".format(UbuntuSecurityBulletinIndexes.BulletinId)
        r.table(UbuntuSecurityCollection.Bulletin).index_create(UbuntuSecurityBulletinIndexes.BulletinId).run(conn)

    if not UbuntuSecurityBulletinIndexes.NameAndVersion in ubuntu_bulletin_list:
        print "Creating index {0}".format(UbuntuSecurityBulletinIndexes.NameAndVersion)
        r.table(UbuntuSecurityCollection.Bulletin).index_create(
            UbuntuSecurityBulletinIndexes.NameAndVersion, lambda x: 
                x[UbuntuSecurityBulletinKeys.Apps].map(lambda y:
                    [y['name'], y['version']]), multi=True).run(conn)

#################################### Agent Queue Indexes ###################################################
    if not AgentQueueIndexes.AgentId in agent_queue_list:
        print "Creating index {0}".format(AgentQueueIndexes.AgentId)
        r.table(QueueCollections.Agent).index_create(AgentQueueIndexes.AgentId).run(conn)

#################################### Group Indexes ###################################################
    if not GroupIndexes.CustomerName in groups_list:
        print "Creating index {0}".format(GroupIndexes.CustomerName)
        r.table(GroupCollections.Groups).index_create(GroupIndexes.CustomerName).run(conn)

    if not GroupIndexes.GroupName in groups_list:
        print "Creating index {0}".format(GroupIndexes.GroupName)
        r.table(GroupCollections.Groups).index_create(GroupIndexes.GroupName).run(conn)

#################################### Groups Per User Indexes ###################################################
    if not GroupsPerUserIndexes.UserName in groups_per_user_list:
        print "Creating index {0}".format(GroupsPerUserIndexes.UserName)
        r.table(GroupCollections.GroupsPerUser).index_create(GroupsPerUserIndexes.UserName).run(conn)

    if not GroupsPerUserIndexes.CustomerName in groups_per_user_list:
        print "Creating index {0}".format(GroupsPerUserIndexes.CustomerName)
        r.table(GroupCollections.GroupsPerUser).index_create(GroupsPerUserIndexes.CustomerName).run(conn)

    if not GroupsPerUserIndexes.GroupName in groups_per_user_list:
        print "Creating index {0}".format(GroupsPerUserIndexes.GroupName)
        r.table(GroupCollections.GroupsPerUser).index_create(GroupsPerUserIndexes.GroupName).run(conn)

    if not GroupsPerUserIndexes.GroupId in groups_per_user_list:
        print "Creating index {0}".format(GroupsPerUserIndexes.GroupId)
        r.table(GroupCollections.GroupsPerUser).index_create(GroupsPerUserIndexes.GroupId).run(conn)

#################################### Customer Per User Indexes ###################################################
    if not CustomerPerUserIndexes.UserName in customer_per_user_list:
        print "Creating index {0}".format(CustomerPerUserIndexes.UserName)
        r.table(CustomerCollections.CustomersPerUser).index_create(CustomerPerUserIndexes.UserName).run(conn)

    if not CustomerPerUserIndexes.CustomerName in customer_per_user_list:
        print "Creating index {0}".format(CustomerPerUserIndexes.CustomerName)
        r.table(CustomerCollections.CustomersPerUser).index_create(CustomerPerUserIndexes.CustomerName).run(conn)

#################################### File Server Indexes ###################################################
    if not FileServerIndexes.CustomerName in file_server_list:
        print "Creating index {0}".format(FileServerIndexes.CustomerName)
        r.table(FileCollections.FileServers).index_create(FileServerIndexes.CustomerName).run(conn)

#################################### Close Database Connection ###################################################
    conn.close()
