#! /usr/bin/env python
from vFense.db.client import r
from time import time

class DbTime(object):

    @staticmethod
    def time_now():
        return(r.epoch_time(int(time())))

    @staticmethod
    def begining_of_time():
        return(r.epoch_time(0.0))


    @staticmethod
    def epoch_time_to_db_time(epoch):
        return(r.epoch_time(epoch))

class DbInfoKeys(object):
    PRIMARY_KEY = 'primary_key'
    INDEXES = 'indexes'
    TYPE = 'type'
    NAME = 'name'
