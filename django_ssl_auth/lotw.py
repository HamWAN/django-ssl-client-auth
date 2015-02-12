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

from pyasn1.codec.der import decoder as der_decoder


def _dictify_dn(dn):
    try:
        return dict(x.split('=') for x in dn.split('/') if '=' in x)
    except ValueError:
        # Since version 2.3.11, Apache HTTPD uses a RFC 2253 compatible format
        d = dict(x.split('=') for x in dn.split(',') if '=' in x)
        callsign = d['1.3.6.1.4.1.12348.1.1']
        if callsign.startswith('#'):
            bin = callsign[1:].decode("hex")
            d['1.3.6.1.4.1.12348.1.1'] = str(der_decoder.decode(bin)[0])
        return d


def user_dict_from_dn(dn):
    d = _dictify_dn(dn)
    ret = dict()
    ret['username'] = d['1.3.6.1.4.1.12348.1.1']
    name = d['CN'].split()
    ret['first_name'] = name[0]
    ret['last_name'] = name[-1]
    ret['email'] = d['emailAddress']
    return ret
