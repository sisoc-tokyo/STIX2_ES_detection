# coding: UTF-8

from os import path
import sys
import json
from elasticsearch import Elasticsearch

es = Elasticsearch(sys.argv[1])

def readfile(report):
    current_dir = path.dirname(__file__)
    f = open(path.join(current_dir, report),'rt',encoding='utf-8')
    rowdata = json.load(f)
    f.close()
    put_data(rowdata)

def put_data(rowdata):
    stixall = rowdata['objects']

    for stixone in stixall:
        idnum = 1
        stixoneid = stixone['id']
        if stixone['type'] == 'indicator':
            # extract patterns delimiter "'"
            stixvalue = stixone['pattern'].split("'")
            for stixonev in stixvalue:
                #stixone = json.dumps(stixone)
                stixid = stixoneid + '-' + str(idnum)
                # check value followed by domain-name or ipv4-addr
                if 'domain-name:' in stixonev:
                    kind = 'domain'
                elif 'url:' in stixonev:
                    kind = 'url'
                elif 'ipv4-addr:' in stixonev:
                    kind = 'ipv4'

                if 'kind' in locals():
                    # case in domain-name
                    if kind == "domain" and '.' in stixonev and ' ' not in stixonev:
                        stixdomain = stixonev
                        es.index(index='stix', doc_type='type', id=stixid, body=stixone)
                        # adding URL field
                        es.update(index='stix', doc_type='type', id=stixid, body={'doc': {'domain': stixdomain}})
                        # create blacklist
                        es.index(index='blacklist', doc_type='type', id=stixdomain, body={'malicious_URL': stixdomain})
                        search_data(stixdomain)
                    # case in url
                    elif kind == "url" and '.' in stixonev and ' ' not in stixonev:
                        stixdomain = stixonev
                        es.index(index='stix', doc_type='type', id=stixid, body=stixone)
                        # adding URL field
                        es.update(index='stix', doc_type='type', id=stixid, body={'doc': {'url': stixdomain}})
                        # create blacklist
                        es.index(index='blacklist', doc_type='type', id=stixdomain, body={'malicious_URL': stixdomain})
                        search_data(stixdomain)
                    # case in ipv4-addr
                    elif kind == "ipv4" and '.' in stixonev and ' ' not in stixonev and '/' not in stixonev:
                        stixip = stixonev
                        es.index(index='stix', doc_type='type', id=stixid, body=stixone)
                        # adding URL field
                        es.update(index='stix', doc_type='type', id=stixid, body={'doc': {'IPaddress': stixip}})
                        # create blacklist
                        es.index(index='blacklist', doc_type='type', id=stixip, body={'malicious_URL': stixip})
                        search_data(stixip)
                idnum += 1
            idnum = 1

def search_data(malinfo):
    # search squid log with malinfo(malicious URL or IPaddress)
    res = es.search(index='squid', body={"from": 0, "size": 10000, 'query': {'match_phrase': {'request': malinfo}}})
    for hit in res['hits']['hits']:
        if 'message' in hit['_source']:
            message = hit['_source']['message']
            id = hit['_id']
            type = hit['_type']
            print(message)
            es.update(index='squid', doc_type=type, id=id, body={'doc': {'indicator': 'matched'}})

if __name__ == '__main__':
    readfile(sys.argv[2])

