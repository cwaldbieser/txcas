#! /usr/bin/env python

from __future__ import print_function
from urlparse import urlparse, parse_qsl

def get_default_port(scheme):
    if scheme.lower() == 'https':
        return 443
    elif scheme.lower() == 'http':
        return 80
    else:
        return None

def normalize_netloc(scheme, netloc):
    if not ':' in netloc:
        default_port = get_default_port(scheme)
        if default_port is not None:
            netloc = "{0}:{1}".format(netloc, default_port)
    return netloc

def are_urls_equal(url0, url1):
    p0 = urlparse(url0)
    p1 = urlparse(url1)
    scheme0 = p0.scheme.lower()
    scheme1 = p1.scheme.lower()
    if scheme0 != scheme1:
        return False
    netloc0 = normalize_netloc(scheme0, p0.netloc)
    netloc1 = normalize_netloc(scheme1, p1.netloc)
    if netloc0 != netloc1:
        return False
    if p0.path != p1.path:
        return False
    if p0.params != p1.params:
        return False
    if p0.fragment != p1.fragment:
        return False
    qs0 = set(parse_qsl(p0.query))
    qs1 = set(parse_qsl(p1.query))
    if qs0 != qs1:
        return False
    return True

if __name__ == "__main__":
    urls = [
        ('http://same.example.com/', 'http://same.example.com/'),
        ('http://different.example.com/', 'http://notthesame.example.net'),
        ('http://differentscheme.example.org/', 'https://differentscheme.example.org/'),
        ('http://sameport.example.net/', 'http://sameport.example.net:80/'),
        ('https://sameport.example.net/', 'https://sameport.example.net:443/'),
        ('http://differentport.example.net/', 'http://differentport.example.net:8080/'),
        ('http://differentpath.example.org/baz', 'http://differentpath.example.org/baz/'),
        (
            'http://differentquery.example.org/baz/?uno=1&dos=2', 
            'http://differentquery.example.org/baz/?uno=one&dos=two'
        ),
        (
            'http://samequery.example.org/baz/?quarter=25&nickle=5&penny=1', 
            'http://samequery.example.org/baz/?quarter=25&nickle=5&penny=1', 
        ),
        (
            'http://samequery.example.org/baz/?nickle=5&quarter=25&penny=1', 
            'http://samequery.example.org/baz/?quarter=25&nickle=5&penny=1', 
        ),
    ]         
    for url0, url1 in urls:
        print("URL A => {0}".format(url0))
        print("URL B => {0}".format(url1))
        print("Equivalent? => {0}".format(are_urls_equal(url0, url1)))
        print("") 
