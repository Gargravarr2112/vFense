class Permissions():
    ADMINISTRATOR = 'administrator'
    INSTALL = 'install'
    UNINSTALL = 'uninstall'
    REBOOT = 'reboot'
    SHUTDOWN = 'shutdown'
    CREATE_TAG = 'create tag'
    REMOVE_TAG = 'remove tag'
    REMOTE_ASSISTANCE = 'remote assistance'
    VALID_PERMISSIONS = (
        ADMINISTRATOR, INSTALL, UNINSTALL, REBOOT,
        SHUTDOWN, CREATE_TAG, REMOVE_TAG, REMOTE_ASSISTANCE
    )
