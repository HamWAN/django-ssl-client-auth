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

def _decode_asn1_hack(asn1):
    # sorry
    return ''.join([chr(int(x, 16)) for x in map(''.join, zip(*[iter(asn1[5:])]*2))])


def _dictify_dn(dn):
    try:
        return dict(x.split('=') for x in dn.split('/') if '=' in x)
    except ValueError:
        # Since version 2.3.11, Apache HTTPD uses a RFC 2253 compatible format
        d = dict(x.split('=') for x in dn.split(',') if '=' in x)
        if d['1.3.6.1.4.1.12348.1.1'].startswith('#13'):
            d['1.3.6.1.4.1.12348.1.1'] = _decode_asn1_hack(d['1.3.6.1.4.1.12348.1.1'])
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
