#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2013 SSH Communication Security Corporation.
# All rights reserved.
# This software is protected by international copyright laws.
#

"""
Utility functions for handling certificates from ARRL Logbook of the World
"""

def _dictify_dn(dn):
    return dict(x.split('=') for x in dn.split('/') if '=' in x)

def user_dict_from_dn(dn):
    d = _dictify_dn(dn)
    ret = dict()
    ret['username'] = d['1.3.6.1.4.1.12348.1.1']
    ret['first_name'], middle, ret['last_name'] = d['CN'].split()
    ret['email'] = d['emailAddress']
    return ret
