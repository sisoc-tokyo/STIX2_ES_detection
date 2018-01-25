import sys
from subprocess import Popen
from elasticsearch import Elasticsearch

# Change IP address and port of Elasticsearch
es = Elasticsearch('localhost:9200')

def search_message(message):
    URL = (message.split(' ')[6])
    src = (message.split(' ')[0])

    res = es.search(index='blacklist', body={"from": 0, "size": 10000, 'query': {'match_all': {}}})
    for hit in res['hits']['hits']:
        if 'malicious_URL' in hit['_source']:
            malURL = hit['_source']['malicious_URL']
            if malURL in URL:
                # Change python command path and program path
                cmd = "/root/.pyenv/shims/python /var/tmp/anaconda3/stix2.0/send_alert.py "+malURL+" "+URL+" "+src
                p = Popen( cmd.strip().split(" ")  )
                print('matched')
                return 'matched'
    else:
        print('-')
        return '-'

if __name__ == '__main__':
    search_message(sys.argv[1])
