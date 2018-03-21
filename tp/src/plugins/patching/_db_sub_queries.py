#!/usr/bin/env python

from vFense.db.client import r
from vFense.plugins.patching import DbCommonAppsKeys


class AppsMerge(object):
    RELEASE_DATE = {
        DbCommonAppsKeys.ReleaseDate: (
            r.row[DbCommonAppsKeys.ReleaseDate].to_epoch_time()
        ),
    }
