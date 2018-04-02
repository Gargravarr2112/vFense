class WindowsSecurityCollection():
    Bulletin = 'windows_security_bulletin'


class WindowsSecurityBulletinKeys():
    Id = 'id'
    DatePosted = 'date_posted'
    BulletinId = 'bulletin_id'
    BulletinKb = 'bulletin_kb'
    BulletinSeverity = 'bulletin_severity'
    BulletinImpact = 'bulletin_impact'
    Details = 'bulletin_details'
    AffectedProduct = 'affected_product'
    ComponentKb = 'component_kb'
    AffectedComponent = 'affected_component'
    ComponentImpact = 'component_impact'
    ComponentSeverity = 'component_severity'
    SupersedesBulletinId = 'supercedes_bulletin_id'
    SupersedesBulletinKb = 'supercedes_bulletin_kb'
    Supersedes = 'supercedes'
    SupportUrl = 'support_url'
    Reboot = 'reboot'
    CveIds = 'cve_ids'

class WindowsSecurityBulletinIndexes():
    BulletinId = 'bulletin_id'
    ComponentKb = 'component_kb'
    CveIds = 'cve_ids'
